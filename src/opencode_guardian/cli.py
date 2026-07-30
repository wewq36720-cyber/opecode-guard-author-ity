from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .environment import prepare_project_environment
from .errors import GuardError
from .facade import Guardian
from .launcher import (
    guard_commands,
    launch_opencode,
    opencode_arguments,
    trusted_executable,
)
from .persistence import StateStore, default_state_dir
from .preflight import assert_guard_environment
from .workspace import WorkspaceManager


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = _dispatch(args)
    except GuardError as exc:
        print(
            json.dumps({"ok": False, "error": exc.as_dict()}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, indent=2))
    return 0


def _dispatch(args: argparse.Namespace) -> dict[str, Any]:
    state_dir = Path(args.state_dir).expanduser().resolve()
    store = StateStore(state_dir / "guard.db")
    workspace = WorkspaceManager(state_dir)
    guardian = Guardian(store, workspace=workspace)
    if args.command == "inspect":
        run_id = args.run
        if not run_id:
            project = Path(args.project).expanduser().resolve(strict=True)
            info = workspace.inspect_project(project)
            run = store.find_active(info.root)
            if run is None:
                raise GuardError("RUN_NOT_FOUND", "Project has no active Guard Run.")
            run_id = run.run_id
        return guardian.status(run_id)
    if args.command == "quality-status":
        return guardian.quality_status(args.run)
    if args.command in {"drive-quality", "confirm-fitness"}:
        status = guardian.status(args.run)
        common = {
            "expected_revision": status["revision"],
            "session_id": args.session,
            "context_digest": status["context_digest"],
            "skill_binding_digest": status["skill_binding"]["digest"],
            "request_id": args.request_id,
        }
        if args.command == "drive-quality":
            return guardian.drive_quality(args.run, **common)
        return guardian.confirm_fitness(args.run, drive_id=args.drive_id, **common)
    if args.command == "review":
        run = guardian.review(
            args.run,
            decision=args.decision,
            reviewer=args.reviewer,
            source=args.source,
        )
        removed = False
        if run.stage.value == "ACCEPTED":
            workspace.remove_worktree(run.project_root, run.worktree, force=True)
            removed = True
        return {**guardian.status(run.run_id), "worktree_removed": removed}
    if args.command == "approve-plan":
        try:
            receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GuardError(
                "APPROVAL_RECEIPT_INVALID", "Plan approval receipt cannot be read."
            ) from exc
        if not isinstance(receipt, dict):
            raise GuardError("APPROVAL_RECEIPT_INVALID", "Plan approval receipt must be an object.")
        result = guardian.approve_plan_receipt(
            args.run,
            expected_revision=args.expected_revision,
            receipt=receipt,
        )
        return {**guardian.status(args.run), "approval": result}
    if args.command == "record-planning-review":
        try:
            receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GuardError("INVALID_REQUEST", "Planning review receipt is invalid.") from exc
        if not isinstance(receipt, dict):
            raise GuardError("INVALID_REQUEST", "Planning review receipt must be an object.")
        result = guardian.record_planning_review_receipt(
            args.run, expected_revision=args.expected_revision, receipt=receipt
        )
        return {**guardian.status(args.run), "planning_review": result}
    if args.command == "open":
        return _open(guardian, args, state_dir)
    raise GuardError("UNKNOWN_COMMAND", f"Unknown command: {args.command}")


def _open(
    guardian: Guardian,
    args: argparse.Namespace,
    state_dir: Path,
) -> dict[str, Any]:
    project = Path(args.project).expanduser().resolve(strict=True)
    info = guardian.workspace.inspect_project(project)
    active = guardian.store.find_active(info.root)
    if active is not None and _is_legacy_frozen_run(guardian, active.run_id):
        if args.dry_run:
            return {
                "status": "LEGACY_RESTART_REQUIRED",
                "project_root": str(info.root),
                "legacy_run_id": active.run_id,
            }
        retired = guardian.store.block_run(
            active.run_id,
            code="LEGACY_RUN_RETIRED",
            message="Legacy frozen Run was retired before starting a current Run.",
            payload={"contract_generation": "pre-certainty"},
        )
        if retired.blocked_code != "LEGACY_RUN_RETIRED":
            raise GuardError(
                "LEGACY_RUN_RETIRE_FAILED",
                "Legacy frozen Run could not be retired.",
                run_id=active.run_id,
            )
        active = None
    requested_session = getattr(args, "session", "")
    if requested_session:
        if active is None:
            raise GuardError(
                "SESSION_NOT_ATTACHED",
                "An explicit OpenCode session requires an existing active Guard Run.",
            )
        guardian.assert_session(active.run_id, requested_session)
    created = False
    if active is None:
        preflight = assert_guard_environment(project)
        environment = prepare_project_environment(project)
        if args.dry_run:
            forbidden: tuple[Path, ...] = (project,)
            trusted_executable(
                args.opencode,
                forbidden_roots=forbidden,
                not_found_code="OPENCODE_NOT_FOUND",
            )
            guard_commands(forbidden)
            return {
                "status": "READY",
                "project_root": str(info.root),
                "base_sha": info.head,
                "environment": {
                    "digest": environment.digest,
                    "image": environment.image,
                    "python": environment.python_version,
                    "checks": [check["id"] for check in environment.checks],
                },
                "isolated_mcp": list(preflight.isolated_mcp),
            }
        run = guardian.start_run(
            project,
            checks=list(environment.checks),
            environment_digest=environment.digest,
        )
        created = True
    else:
        if args.dry_run:
            guardian.assert_registered_checks_available(active.run_id)
            return {"status": "RESUMABLE", **guardian.status(active.run_id)}
        run = guardian.resume_run(project)
    try:
        if created:
            actual_environment = prepare_project_environment(run.worktree)
            if actual_environment.digest != environment.digest:
                raise GuardError(
                    "PROJECT_ENVIRONMENT_CHANGED",
                    "Project environment changed before the Guard worktree was created.",
                )
        preflight = assert_guard_environment(run.worktree)
        forbidden = (run.project_root, run.worktree)
        executable = trusted_executable(
            args.opencode,
            forbidden_roots=forbidden,
            not_found_code="OPENCODE_NOT_FOUND",
        )
        authority_command, mcp_command = guard_commands(forbidden)
        arguments = opencode_arguments(
            args.opencode_args,
            session_id=requested_session,
        )
        return launch_opencode(
            executable,
            arguments,
            run,
            state_dir,
            config_content=preflight.config_content,
            authority_command=authority_command,
            mcp_command=mcp_command,
        )
    except GuardError as exc:
        if created:
            cleanup_errors: list[str] = []
            try:
                guardian.workspace.remove_worktree(
                    run.project_root,
                    run.worktree,
                    force=True,
                )
            except Exception as cleanup_error:
                cleanup_errors.append(f"worktree:{type(cleanup_error).__name__}")
            try:
                guardian.store.cancel_startup(run.run_id)
            except Exception as cleanup_error:
                cleanup_errors.append(f"run:{type(cleanup_error).__name__}")
            if cleanup_errors:
                raise GuardError(
                    "STARTUP_CLEANUP_FAILED",
                    "OpenCode failed and startup cleanup was incomplete.",
                    launch_error=exc.code,
                    cleanup_error=cleanup_errors,
                ) from exc
        raise


def _is_legacy_frozen_run(guardian: Guardian, run_id: str) -> bool:
    try:
        artifact = guardian.store.get_artifact(run_id)
    except GuardError as exc:
        if exc.code == "ARTIFACT_NOT_FOUND":
            return False
        raise
    return "certainty" not in artifact["body"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opencode-guard")
    parser.add_argument("--state-dir", default=str(default_state_dir()))
    subparsers = parser.add_subparsers(dest="command", required=True)

    open_command = subparsers.add_parser("open")
    open_command.add_argument("--project", required=True)
    open_command.add_argument("--opencode", default="opencode")
    open_command.add_argument("--session", default="")
    open_command.add_argument("--dry-run", action="store_true")
    open_command.add_argument("opencode_args", nargs=argparse.REMAINDER)

    inspect = subparsers.add_parser("inspect")
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--run", default="")
    target.add_argument("--project", default="")

    quality_status = subparsers.add_parser("quality-status")
    quality_status.add_argument("--run", required=True)

    drive_quality = subparsers.add_parser("drive-quality")
    drive_quality.add_argument("--run", required=True)
    drive_quality.add_argument("--session", required=True)
    drive_quality.add_argument("--request-id", required=True)

    confirm_fitness = subparsers.add_parser("confirm-fitness")
    confirm_fitness.add_argument("--run", required=True)
    confirm_fitness.add_argument("--session", required=True)
    confirm_fitness.add_argument("--request-id", required=True)
    confirm_fitness.add_argument("--drive-id", required=True)

    review = subparsers.add_parser("review")
    review.add_argument("--run", required=True)
    review.add_argument(
        "--decision",
        choices=("approve", "changes-requested"),
        required=True,
    )
    review.add_argument("--reviewer", required=True)
    review.add_argument(
        "--source",
        choices=("user", "ci", "independent-review"),
        required=True,
    )

    approve_plan = subparsers.add_parser("approve-plan")
    approve_plan.add_argument("--run", required=True)
    approve_plan.add_argument("--expected-revision", required=True, type=int)
    approve_plan.add_argument("--receipt", required=True)

    planning_review = subparsers.add_parser("record-planning-review")
    planning_review.add_argument("--run", required=True)
    planning_review.add_argument("--expected-revision", required=True, type=int)
    planning_review.add_argument("--receipt", required=True)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
