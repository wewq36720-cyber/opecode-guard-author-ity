from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Protocol

from .contracts import (
    RunRecord,
    Stage,
    normalize_packet,
    normalize_planning_artifact,
)
from .errors import GuardError
from .evidence import evidence_from_result, evidence_set_digest
from .integrity import digest_json
from .persistence import StateStore
from .quality import project_quality_status
from .sandbox import DockerSandbox, SandboxResult
from .workspace import ProjectInfo, WorkspaceManager, WorkspaceSnapshot

READ_TOOLS = frozenset({"read", "glob", "grep", "list", "lsp", "question"})
WRITE_TOOLS = frozenset({"edit", "write", "patch", "apply_patch", "multiedit", "multi_edit"})
DENIED_TOOLS = frozenset({"bash", "task", "shell", "command", "external_directory"})
PROTECTED_PATHS = (".git", ".opencode")

_PHASE_SKILL_INSTRUCTIONS = {
    Stage.PLANNING.value: "Submit one complete frozen packet before editing.",
    Stage.IMPLEMENTING.value: "Edit only frozen paths and use the Guard write lease.",
    Stage.VERIFYING.value: "Use trusted verification evidence; do not write.",
    Stage.REVIEW_REQUIRED.value: "Use current evidence and wait for external acceptance.",
    Stage.ACCEPTED.value: "Read-only accepted Run; do not mutate state.",
}


def project_guard_context(
    base: dict[str, Any],
    *,
    lease: Mapping[str, Any] | None,
    evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    stage = str(base["stage"])
    active_phase = str(base.get("active_phase", ""))
    skill_source = {
        "skill_id": f"opencode-guard/{stage.lower()}",
        "version": "1",
        "stage": stage,
        "phase_id": active_phase,
        "packet_version": int(base.get("packet_version", 0)),
        "packet_digest": str(base.get("packet_digest", "")),
        "instructions": _PHASE_SKILL_INSTRUCTIONS.get(stage, "Read-only unknown stage."),
    }
    skill_binding = {**skill_source, "digest": digest_json(skill_source)}
    failed = [
        {
            "check_id": str(item.get("check_id", "")),
            "exit_code": int(item.get("exit_code", 0)),
            "timed_out": bool(item.get("timed_out", False)),
            "created_at": str(item.get("created_at", "")),
        }
        for item in evidence
        if int(item.get("exit_code", 0)) != 0 or bool(item.get("timed_out", False))
    ]
    context = {
        **base,
        "source_revision": int(base["revision"]),
        "skill_binding": skill_binding,
        "lease": {
            "active": lease is not None,
            "phase_id": str(lease.get("phase_id", "")) if lease else "",
            "revision": int(lease.get("revision", 0)) if lease else 0,
        },
        "recent_failed_evidence": failed[-8:],
    }
    context["context_digest"] = digest_json(
        {key: value for key, value in context.items() if key not in {"context_digest", "evidence"}}
    )
    return context


class WorkspacePort(Protocol):
    def inspect_project(self, project_root: Path) -> ProjectInfo: ...

    def create_worktree(self, project: ProjectInfo, run_id: str) -> Path: ...

    def snapshot(
        self,
        project_root: Path,
        worktree: Path,
        base_sha: str,
    ) -> WorkspaceSnapshot: ...

    def remove_worktree(
        self,
        project_root: Path,
        worktree: Path,
        *,
        force: bool = False,
    ) -> None: ...


class SandboxPort(Protocol):
    def assert_images_available(self, images: list[str]) -> str: ...

    def run(
        self,
        *,
        worktree: Path,
        run_id: str,
        check: Mapping[str, Any],
    ) -> SandboxResult: ...


class Guardian:
    """Single public application facade for the minimal Guard runtime."""

    def __init__(
        self,
        store: StateStore,
        *,
        workspace: WorkspacePort | None = None,
        sandbox: SandboxPort | None = None,
    ) -> None:
        self.store = store
        self.workspace = workspace or WorkspaceManager(store.database.parent)
        self.sandbox = sandbox or DockerSandbox()

    def start_run(
        self,
        project_root: Path,
        *,
        checks: list[dict[str, Any]],
        environment_digest: str,
        run_id: str | None = None,
    ) -> RunRecord:
        project = self.workspace.inspect_project(project_root)
        active = self.store.find_active(project.root)
        if active is not None:
            raise GuardError(
                "RUN_ALREADY_ACTIVE",
                "Project already has an active Run; use open to resume it.",
                run_id=active.run_id,
            )
        selected_id = run_id or f"run-{uuid.uuid4().hex[:20]}"
        worktree = self.workspace.create_worktree(project, selected_id)
        try:
            snapshot = self.workspace.snapshot(project.root, worktree, project.head)
            if snapshot.changed_paths:
                raise GuardError(
                    "WORKTREE_NOT_CLEAN",
                    "New Guard worktree differs from its Git base.",
                    paths=list(snapshot.changed_paths),
                )
            return self.store.create_run(
                run_id=selected_id,
                project_root=project.root,
                git_common_dir=project.git_common_dir,
                worktree=worktree,
                base_sha=project.head,
                environment_digest=environment_digest,
                workspace_digest=snapshot.digest,
                checks=checks,
            )
        except Exception as exc:
            try:
                self.workspace.remove_worktree(project.root, worktree, force=True)
            except Exception as cleanup_error:
                raise GuardError(
                    "RUN_START_CLEANUP_FAILED",
                    "Run creation failed and its worktree could not be removed.",
                    start_error=exc.code if isinstance(exc, GuardError) else type(exc).__name__,
                    cleanup_error=type(cleanup_error).__name__,
                ) from exc
            if isinstance(exc, GuardError):
                raise
            raise GuardError(
                "RUN_START_FAILED",
                "Run could not be registered after its worktree was created.",
                operation_error=type(exc).__name__,
            ) from exc

    def resume_run(self, project_root: Path) -> RunRecord:
        project = self.workspace.inspect_project(project_root)
        run = self.store.find_active(project.root)
        if run is None:
            raise GuardError("RUN_NOT_FOUND", "Project has no active Guard Run.")
        if run.base_sha != project.head:
            raise GuardError(
                "BASELINE_CHANGED",
                "Project HEAD changed after the active Run was created.",
                expected=run.base_sha,
                actual=project.head,
            )
        self.assert_registered_checks_available(run.run_id)
        self.reconcile_workspace(run.run_id)
        return self.store.get_run(run.run_id)

    def bind_task(
        self,
        run_id: str,
        *,
        expected_revision: int,
        task: str,
        session_id: str,
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> RunRecord:
        self._assert_context(
            run_id,
            expected_revision,
            context_digest,
            skill_binding_digest,
        )
        return self.store.bind_task(
            run_id,
            expected_revision=expected_revision,
            task=task,
            session_id=session_id,
        )

    def assert_session(self, run_id: str, session_id: str) -> RunRecord:
        return self.store.assert_session(run_id, session_id)

    def attach_session(
        self,
        run_id: str,
        session_id: str,
        *,
        expected_revision: int,
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> RunRecord:
        self._assert_context(run_id, expected_revision, context_digest, skill_binding_digest)
        return self.store.attach_session(
            run_id,
            session_id,
            expected_revision=expected_revision,
        )

    def submit_packet(
        self,
        run_id: str,
        *,
        expected_revision: int,
        body: dict[str, Any],
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> RunRecord:
        raise GuardError(
            "LEGACY_ROUTE_FORBIDDEN",
            "submit_packet is retired; submit governed planning artifacts instead.",
        )

    def submit_baseline(
        self,
        run_id: str,
        *,
        expected_revision: int,
        body: dict[str, Any],
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> dict[str, Any]:
        return self._submit_planning_artifact(
            run_id,
            expected_revision=expected_revision,
            body=body,
            expected_kind="BASELINE",
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )

    def submit_spec(
        self,
        run_id: str,
        *,
        expected_revision: int,
        body: dict[str, Any],
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> dict[str, Any]:
        return self._submit_planning_artifact(
            run_id,
            expected_revision=expected_revision,
            body=body,
            expected_kind="SPEC",
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )

    def submit_plan(
        self,
        run_id: str,
        *,
        expected_revision: int,
        body: dict[str, Any],
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> dict[str, Any]:
        return self._submit_planning_artifact(
            run_id,
            expected_revision=expected_revision,
            body=body,
            expected_kind="PLAN",
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )

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
        raise GuardError(
            "LEGACY_ROUTE_FORBIDDEN",
            "approve_plan is retired; use a typed external approval receipt.",
        )

    def approve_plan_receipt(
        self,
        run_id: str,
        *,
        expected_revision: int,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        self._mutable_run(run_id, expected_revision=expected_revision)
        recorded = self.store.record_plan_approval_receipt(
            run_id,
            expected_revision=expected_revision,
            receipt=receipt,
        )
        return self.store.consume_plan_approval_receipt(
            run_id,
            expected_revision=int(recorded["revision"]),
            approval_id=str(recorded["receipt"]["approval_id"]),
        )

    def record_planning_review_receipt(
        self,
        run_id: str,
        *,
        expected_revision: int,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        self._mutable_run(run_id, expected_revision=expected_revision)
        return self.store.record_planning_review_receipt(
            run_id, expected_revision=expected_revision, receipt=receipt
        )

    def _submit_planning_artifact(
        self,
        run_id: str,
        *,
        expected_revision: int,
        body: dict[str, Any],
        expected_kind: str,
        context_digest: str,
        skill_binding_digest: str,
    ) -> dict[str, Any]:
        try:
            self._assert_context(run_id, expected_revision, context_digest, skill_binding_digest)
            run = self._mutable_run(run_id, expected_revision=expected_revision)
            artifact = normalize_planning_artifact(body)
            if artifact["kind"] != expected_kind:
                raise GuardError(
                    "INVALID_PLANNING_ARTIFACT", "Planning artifact kind does not match entrypoint."
                )
            if expected_kind == "PLAN":
                checks = {item["id"] for item in self.store.list_checks(run_id)}
                packet = normalize_packet(
                    artifact["implementation"]["packet"], available_checks=checks
                )
                if packet != artifact["implementation"]["packet"]:
                    raise GuardError(
                        "INVALID_PLANNING_ARTIFACT",
                        "PLAN implementation is not bound to registered checks.",
                    )
                self._assert_unambiguous_path_scopes(run.worktree, packet)
                self.sandbox.assert_images_available(
                    [item["image"] for item in self.store.list_checks(run_id)]
                )
            return self.store.store_planning_artifact(
                run_id, expected_revision=expected_revision, body=artifact
            )
        except GuardError as error:
            revision = self.store.record_planning_submission_rejection(
                run_id,
                kind=expected_kind,
                input_digest=digest_json(body) if isinstance(body, dict) else "",
                error_code=error.code,
            )
            if revision is None:
                raise
            raise GuardError(
                error.code, error.message, **error.details, current_revision=revision
            ) from error

    def plan_approval(
        self,
        run_id: str,
        *,
        base_packet_digest: str,
        candidate_packet_digest: str,
        added_paths: list[str],
    ) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        canonical_paths = sorted(
            {self._normalize_scope_declaration(run, path) for path in added_paths}
        )
        return self.store.get_plan_approval(
            run_id,
            base_packet_digest=base_packet_digest,
            candidate_packet_digest=candidate_packet_digest,
            added_paths=canonical_paths,
        )

    def authorize_tool(
        self,
        run_id: str,
        tool_name: str,
        paths: list[str],
        *,
        call_id: str,
        session_id: str = "",
        expected_revision: int | None = None,
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        if tool_name in DENIED_TOOLS or tool_name not in READ_TOOLS | WRITE_TOOLS:
            raise GuardError("TOOL_DENIED", f"Tool is denied in guarded mode: {tool_name}")
        participant = _bounded(session_id or run.session_id, "session_id", 200)
        run = self.store.assert_session(run_id, participant)
        revision = run.revision if expected_revision is None else expected_revision
        self._assert_context(run_id, revision, context_digest, skill_binding_digest)
        if tool_name in READ_TOOLS:
            return {"allowed": True, "revision": run.revision}
        run = self._mutable_run(run_id)
        if run.stage is not Stage.IMPLEMENTING or not run.active_phase:
            raise GuardError("WRITE_NOT_ALLOWED", "Writes require an active implementation phase.")
        if not paths:
            raise GuardError("WRITE_PATH_REQUIRED", "Write tools must declare target paths.")
        declared = [self._normalize_path(run, path) for path in paths]
        phase = self._active_phase(run_id, run.active_phase)
        self._assert_paths_allowed(declared, set(phase["allowed_paths"]))
        snapshot = self.workspace.snapshot(run.project_root, run.worktree, run.base_sha)
        if snapshot.digest != run.workspace_digest:
            self.store.block_run(
                run_id,
                code="UNATTRIBUTED_WORKSPACE_CHANGE",
                message="Workspace changed without a valid write lease.",
                payload={"paths": list(snapshot.changed_paths)},
            )
            raise GuardError(
                "UNATTRIBUTED_WORKSPACE_CHANGE",
                "Workspace changed before write authorization.",
            )
        return self.store.create_write_lease(
            run_id,
            expected_revision=run.revision,
            session_id=participant,
            call_id=_bounded(call_id, "call_id", 200),
            tool_name=tool_name,
            declared_paths=declared,
            before_digest=snapshot.digest,
            before_files=list(snapshot.changed_files),
        )

    def post_tool(
        self,
        run_id: str,
        *,
        expected_revision: int,
        tool_name: str,
        call_id: str,
        session_id: str = "",
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> RunRecord:
        run = self._mutable_run(run_id)
        participant = _bounded(session_id or run.session_id, "session_id", 200)
        self.store.assert_session(run_id, participant)
        self._assert_context(
            run_id,
            expected_revision,
            context_digest,
            skill_binding_digest,
        )
        lease = self.store.get_write_lease(run_id)
        if lease is None or lease["call_id"] != call_id or lease["tool_name"] != tool_name:
            self.store.block_run(
                run_id,
                code="MISSING_WRITE_LEASE",
                message="Write completed without its matching authorization.",
            )
            raise GuardError(
                "MISSING_WRITE_LEASE",
                "Write completed without its matching authorization.",
            )
        if lease["session_id"] != participant:
            raise GuardError("WRITE_BUSY", "Write lease belongs to another participant.")
        snapshot = self.workspace.snapshot(run.project_root, run.worktree, run.base_sha)
        actual_paths = _changed_paths(
            dict(lease["before_files"]),
            dict(snapshot.changed_files),
        )
        if not _paths_within(actual_paths, lease["declared_paths"]):
            self.store.block_run(
                run_id,
                code="WRITE_SCOPE_VIOLATION",
                message="Actual changes exceeded declared write paths.",
                payload={"actual_paths": actual_paths},
            )
            raise GuardError(
                "WRITE_SCOPE_VIOLATION",
                "Actual changes exceeded the declared write paths.",
                actual_paths=actual_paths,
            )
        phase = self._active_phase(run_id, lease["phase_id"])
        try:
            self._assert_paths_allowed(actual_paths, set(phase["allowed_paths"]))
        except GuardError:
            self.store.block_run(
                run_id,
                code="WRITE_SCOPE_VIOLATION",
                message="Actual changes exceeded the frozen phase paths.",
                payload={"actual_paths": actual_paths},
            )
            raise
        return self.store.finish_write(
            run_id,
            expected_revision=expected_revision,
            session_id=participant,
            call_id=call_id,
            workspace_digest=snapshot.digest,
            actual_paths=actual_paths,
        )

    def complete_phase(
        self,
        run_id: str,
        *,
        expected_revision: int,
        phase_id: str,
        outcome: str,
        rationale: str,
        context_digest: str = "",
        skill_binding_digest: str = "",
    ) -> RunRecord:
        self._assert_context(
            run_id,
            expected_revision,
            context_digest,
            skill_binding_digest,
        )
        run = self.store.complete_phase(
            run_id,
            expected_revision=expected_revision,
            phase_id=phase_id,
            outcome=outcome,
            rationale=rationale,
        )
        return self._verify(run) if run.stage is Stage.VERIFYING else run

    def review(
        self,
        run_id: str,
        *,
        decision: str,
        reviewer: str,
        source: str,
    ) -> RunRecord:
        run = self.store.get_run(run_id)
        if decision == "changes-requested":
            _review_fields(reviewer, source)
            if run.stage is not Stage.REVIEW_REQUIRED:
                raise GuardError("REVIEW_NOT_READY", "Run is not waiting for external review.")
            return self.store.reopen_last_phase(
                run_id,
                event="CHANGES_REQUESTED",
                payload={"reviewer": reviewer, "source": source},
                expected_revision=run.revision,
                expected_packet_digest=run.packet_digest,
                expected_workspace_digest=run.workspace_digest,
                expected_evidence_digest=run.evidence_digest,
            )
        if decision != "approve":
            raise GuardError("INVALID_REVIEW", "Unknown review decision.")
        _review_fields(reviewer, source)
        snapshot = self.workspace.snapshot(run.project_root, run.worktree, run.base_sha)
        return self.store.approve(
            run_id,
            reviewer=reviewer,
            source=source,
            expected_revision=run.revision,
            expected_packet_digest=run.packet_digest,
            expected_workspace_digest=run.workspace_digest,
            expected_evidence_digest=run.evidence_digest,
            actual_workspace_digest=snapshot.digest,
        )

    def status(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        artifact = self.store.get_artifact(run_id) if run.packet_digest else None
        history = self.store.list_artifact_history(run_id) if run.packet_digest else []
        phases = self.store.list_phases(run_id) if run.packet_digest else []
        active = next((phase for phase in phases if phase["status"] == "ACTIVE"), None)
        evidence = self.store.list_evidence(run_id)
        base = {
            "run_id": run.run_id,
            "project_root": str(run.project_root),
            "worktree": str(run.worktree),
            "base_sha": run.base_sha,
            "task": run.task,
            "stage": run.stage.value,
            "revision": run.revision,
            "packet_version": int(artifact["version"]) if artifact else 0,
            "packet_digest": run.packet_digest,
            "previous_packet_count": max(0, len(history) - 1),
            "environment_digest": run.environment_digest,
            "workspace_digest": run.workspace_digest,
            "evidence_digest": run.evidence_digest,
            "active_phase": run.active_phase,
            "allowed_paths": active["allowed_paths"] if active else [],
            "phases": phases,
            "available_checks": [item["id"] for item in self.store.list_checks(run_id)],
            "evidence": evidence,
            "blocked": {
                "code": run.blocked_code,
                "message": run.blocked_message,
            },
        }
        return project_guard_context(
            base,
            lease=self.store.get_write_lease(run_id),
            evidence=evidence,
        )

    def quality_status(self, run_id: str) -> dict[str, Any]:
        return project_quality_status(self.status(run_id))

    def drive_quality(
        self,
        run_id: str,
        *,
        expected_revision: int,
        request_id: str,
        session_id: str,
        context_digest: str,
        skill_binding_digest: str,
    ) -> dict[str, Any]:
        self.store.assert_session(run_id, session_id)
        replay = self.store.get_quality_drive(run_id, request_id)
        if replay is not None:
            return replay
        self._assert_context(run_id, expected_revision, context_digest, skill_binding_digest)
        result = self.quality_status(run_id)
        drive_id = f"d-{digest_json({'run_id': run_id, 'request_id': request_id})[:32]}"
        return self.store.drive_quality(
            run_id,
            expected_revision=expected_revision,
            request_id=request_id,
            drive_id=drive_id,
            result=result,
        )

    def confirm_fitness(
        self,
        run_id: str,
        *,
        expected_revision: int,
        request_id: str,
        drive_id: str,
        session_id: str,
        context_digest: str,
        skill_binding_digest: str,
    ) -> dict[str, Any]:
        self.store.assert_session(run_id, session_id)
        replay = self.store.get_fitness_confirmation(run_id, request_id)
        if replay is not None:
            return replay
        self._assert_context(run_id, expected_revision, context_digest, skill_binding_digest)
        confirmation_id = f"c-{digest_json({'run_id': run_id, 'request_id': request_id})[:32]}"
        return self.store.confirm_fitness(
            run_id,
            expected_revision=expected_revision,
            request_id=request_id,
            confirmation_id=confirmation_id,
            drive_id=drive_id,
        )

    def _assert_context(
        self,
        run_id: str,
        expected_revision: int,
        context_digest: str,
        skill_binding_digest: str,
    ) -> None:
        if not context_digest and not skill_binding_digest:
            return
        current = self.status(run_id)
        if (
            expected_revision != current["source_revision"]
            or context_digest != current["context_digest"]
        ):
            raise GuardError(
                "REVISION_CONFLICT",
                "Guard context is stale; reread context before retrying.",
            )
        if skill_binding_digest != current["skill_binding"]["digest"]:
            raise GuardError("SKILL_BINDING_INVALID", "Guard phase Skill binding is invalid.")

    def artifact(self, run_id: str, *, version: int | None = None) -> dict[str, Any]:
        return self.store.get_artifact(run_id, version=version)

    def artifact_history(self, run_id: str) -> list[dict[str, Any]]:
        return self.store.list_artifact_history(run_id)

    def evidence(self, run_id: str) -> list[dict[str, Any]]:
        return self.store.list_evidence(run_id)

    def assert_registered_checks_available(self, run_id: str) -> str:
        checks = self.store.list_checks(run_id)
        return self.sandbox.assert_images_available([item["image"] for item in checks])

    def reconcile_workspace(self, run_id: str) -> RunRecord:
        run = self.store.get_run(run_id)
        snapshot = self.workspace.snapshot(run.project_root, run.worktree, run.base_sha)
        lease = self.store.get_write_lease(run_id)
        if lease is not None:
            if snapshot.digest == lease["before_digest"]:
                return self.store.cancel_unchanged_lease(run_id, lease["call_id"])
            return self.post_tool(
                run_id,
                expected_revision=lease["revision"],
                tool_name=lease["tool_name"],
                call_id=lease["call_id"],
                session_id=lease["session_id"],
            )
        if snapshot.digest != run.workspace_digest:
            return self.store.block_run(
                run_id,
                code="UNATTRIBUTED_WORKSPACE_CHANGE",
                message="Workspace changed outside the guarded hook pair.",
                payload={"paths": list(snapshot.changed_paths)},
            )
        return run

    def _verify(self, run: RunRecord) -> RunRecord:
        snapshot = self.workspace.snapshot(run.project_root, run.worktree, run.base_sha)
        if snapshot.digest != run.workspace_digest:
            self.store.block_run(
                run.run_id,
                code="UNATTRIBUTED_WORKSPACE_CHANGE",
                message="Workspace changed before trusted verification.",
                payload={"paths": list(snapshot.changed_paths)},
            )
            raise GuardError(
                "UNATTRIBUTED_WORKSPACE_CHANGE",
                "Workspace changed before trusted verification.",
            )
        phases = self.store.list_phases(run.run_id)
        selected_ids = list(
            dict.fromkeys(check_id for phase in phases for check_id in phase["check_ids"])
        )
        checks = {
            check["id"]: check
            for check in self.store.list_checks(run.run_id)
            if check["id"] in selected_ids
        }
        if set(checks) != set(selected_ids):
            raise GuardError("UNTRUSTED_CHECK", "Frozen phase references an unknown check.")
        self.sandbox.assert_images_available([checks[item]["image"] for item in selected_ids])
        collected = []
        previews: dict[str, str] = {}
        for check_id in selected_ids:
            check = checks[check_id]
            result = self.sandbox.run(
                worktree=run.worktree,
                run_id=run.run_id,
                check=check,
            )
            requirement_ids, acceptance_ids = _check_mapping(phases, check_id)
            collected.append(
                evidence_from_result(
                    run_id=run.run_id,
                    check_id=check_id,
                    requirement_ids=requirement_ids,
                    acceptance_ids=acceptance_ids,
                    base_sha=run.base_sha,
                    artifact_set=run.packet_digest,
                    workspace=snapshot,
                    result=result,
                )
            )
            previews[check_id] = result.output
        return self.store.finish_verification(
            run.run_id,
            evidence=collected,
            set_digest=evidence_set_digest(collected),
            previews=previews,
        )

    def _mutable_run(
        self,
        run_id: str,
        *,
        expected_revision: int | None = None,
    ) -> RunRecord:
        run = self.store.get_run(run_id)
        if expected_revision is not None and run.revision != expected_revision:
            raise GuardError(
                "REVISION_CONFLICT",
                "Run revision changed before this operation.",
                expected=expected_revision,
                actual=run.revision,
            )
        if run.blocked_code:
            raise GuardError(
                "RUN_BLOCKED",
                "Blocked Run cannot be changed.",
                blocked_code=run.blocked_code,
            )
        if run.stage is Stage.ACCEPTED:
            raise GuardError("RUN_ACCEPTED", "Accepted Run is immutable.")
        return run

    def _active_phase(self, run_id: str, phase_id: str) -> dict[str, Any]:
        phase = next(
            (item for item in self.store.list_phases(run_id) if item["id"] == phase_id),
            None,
        )
        if phase is None or phase["status"] != "ACTIVE":
            raise GuardError("PHASE_NOT_ACTIVE", "Frozen phase is not active.")
        return phase

    @staticmethod
    def _normalize_path(run: RunRecord, raw: str) -> str:
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw or len(raw) > 500:
            raise GuardError("INVALID_PATH", "Tool path must be bounded text.")
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = run.worktree / candidate
        resolved = candidate.resolve(strict=False)
        try:
            relative = resolved.relative_to(run.worktree.resolve(strict=True)).as_posix()
        except ValueError as exc:
            raise GuardError("PATH_ESCAPE", "Tool path escapes the guarded worktree.") from exc
        if not relative or any(
            relative == protected or relative.startswith(f"{protected}/")
            for protected in PROTECTED_PATHS
        ):
            raise GuardError("PROTECTED_PATH", f"Guard protects this path: {relative}")
        return relative

    @staticmethod
    def _normalize_scope_declaration(run: RunRecord, raw: str) -> str:
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw or len(raw) > 500:
            raise GuardError("INVALID_PATH", "Plan scope path must be bounded text.")
        normalized = raw.replace("\\", "/").strip().rstrip("/")
        tree = normalized.endswith("/**")
        root = normalized[:-3].rstrip("/") if tree else normalized
        if not root or root == "." or any(marker in root for marker in "*?[]"):
            raise GuardError(
                "INVALID_PATH",
                "Plan scope must be an exact path or an explicit directory tree.",
            )
        relative = Guardian._normalize_path(run, root)
        return f"{relative}/**" if tree else relative

    @staticmethod
    def _assert_paths_allowed(paths: list[str], patterns: set[str]) -> None:
        denied = [path for path in paths if not any(fnmatchcase(path, item) for item in patterns)]
        if denied:
            raise GuardError(
                "PATH_NOT_ALLOWED",
                "Paths are outside the frozen phase scope.",
                paths=denied,
            )

    @staticmethod
    def _assert_unambiguous_path_scopes(worktree: Path, packet: dict[str, Any]) -> None:
        scopes = {
            path
            for item in [*packet["acceptance"], *packet["phases"]]
            for path in item.get("required_paths", item.get("allowed_paths", []))
        }
        ambiguous = sorted(
            path for path in scopes if not path.endswith("/**") and (worktree / path).is_dir()
        )
        if ambiguous:
            raise GuardError(
                "AMBIGUOUS_PATH_SCOPE",
                "Existing directories must use an explicit /** tree scope.",
                paths=ambiguous,
            )


def _changed_paths(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(
        path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
    )


def _paths_within(actual: list[str], declared: list[str]) -> bool:
    return all(
        any(path == root or path.startswith(f"{root.rstrip('/')}/") for root in declared)
        for path in actual
    )


def _check_mapping(phases: list[dict[str, Any]], check_id: str) -> tuple[list[str], list[str]]:
    requirements = {
        item
        for phase in phases
        if check_id in phase["check_ids"]
        for item in phase["requirement_ids"]
    }
    acceptance = {
        item
        for phase in phases
        if check_id in phase["check_ids"]
        for item in phase["acceptance_ids"]
    }
    return sorted(requirements), sorted(acceptance)


def _bounded(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        raise GuardError("INVALID_CONTROL_VALUE", f"{field} must be bounded text.")
    return value.strip()


def _review_fields(reviewer: str, source: str) -> None:
    _bounded(reviewer, "reviewer", 200)
    if source not in {"user", "ci", "independent-review"}:
        raise GuardError("INVALID_REVIEW", "Unknown review source.")


__all__ = ["Guardian"]
