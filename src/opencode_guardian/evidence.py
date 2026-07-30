from __future__ import annotations

from dataclasses import asdict, dataclass

from .integrity import digest_json
from .sandbox import SandboxResult
from .workspace import WorkspaceSnapshot


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    run_id: str
    check_id: str
    requirement_ids: tuple[str, ...]
    acceptance_ids: tuple[str, ...]
    base_sha: str
    artifact_set_digest: str
    workspace_digest: str
    command_digest: str
    image_digest: str
    output_digest: str
    exit_code: int
    timed_out: bool
    duration_ms: int

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def digest(self) -> str:
        return digest_json(asdict(self))


def evidence_from_result(
    *,
    run_id: str,
    check_id: str,
    requirement_ids: list[str],
    acceptance_ids: list[str],
    base_sha: str,
    artifact_set: str,
    workspace: WorkspaceSnapshot,
    result: SandboxResult,
) -> VerificationEvidence:
    return VerificationEvidence(
        run_id=run_id,
        check_id=check_id,
        requirement_ids=tuple(sorted(requirement_ids)),
        acceptance_ids=tuple(sorted(acceptance_ids)),
        base_sha=base_sha,
        artifact_set_digest=artifact_set,
        workspace_digest=workspace.digest,
        command_digest=result.command_digest,
        image_digest=result.image_digest,
        output_digest=result.output_digest,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        duration_ms=result.duration_ms,
    )


def evidence_set_digest(evidence: list[VerificationEvidence]) -> str:
    return digest_json([asdict(item) for item in sorted(evidence, key=lambda item: item.check_id)])
