from __future__ import annotations

from opencode_guardian.evidence import evidence_from_result, evidence_set_digest
from opencode_guardian.sandbox import SandboxResult
from opencode_guardian.workspace import WorkspaceSnapshot


def result() -> SandboxResult:
    return SandboxResult(
        exit_code=0,
        timed_out=False,
        duration_ms=12,
        output="passed",
        output_digest="a" * 64,
        output_bytes=6,
        output_truncated=False,
        command_digest="b" * 64,
        image_digest="python@sha256:" + "c" * 64,
    )


def test_evidence_changes_with_workspace_and_artifact_versions() -> None:
    first = evidence_from_result(
        run_id="run-1",
        check_id="test",
        requirement_ids=["R1"],
        acceptance_ids=["A1"],
        base_sha="d" * 40,
        artifact_set="e" * 64,
        workspace=WorkspaceSnapshot(("src/app.py",), "f" * 64, 1, 10),
        result=result(),
    )
    changed_workspace = evidence_from_result(
        run_id="run-1",
        check_id="test",
        requirement_ids=["R1"],
        acceptance_ids=["A1"],
        base_sha="d" * 40,
        artifact_set="e" * 64,
        workspace=WorkspaceSnapshot(("src/app.py",), "0" * 64, 1, 10),
        result=result(),
    )
    changed_artifact = evidence_from_result(
        run_id="run-1",
        check_id="test",
        requirement_ids=["R1"],
        acceptance_ids=["A1"],
        base_sha="d" * 40,
        artifact_set="1" * 64,
        workspace=WorkspaceSnapshot(("src/app.py",), "f" * 64, 1, 10),
        result=result(),
    )
    assert first.passed is True
    assert evidence_set_digest([first]) != evidence_set_digest([changed_workspace])
    assert evidence_set_digest([first]) != evidence_set_digest([changed_artifact])
