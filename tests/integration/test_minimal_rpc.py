from __future__ import annotations

import pytest

from opencode_guardian.errors import GuardError
from opencode_guardian.rpc import ALLOWED_OPERATIONS, _dispatch


class FakeGuardian:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def status(self, run_id: str) -> dict[str, object]:
        return {
            "run_id": run_id,
            "revision": 1,
            "source_revision": 1,
            "context_digest": "context-1",
            "skill_binding": {"digest": "skill-1"},
        }

    def quality_status(self, run_id: str) -> dict[str, object]:
        return {"run_id": run_id, "readiness": "NEEDS_PACKET"}

    def drive_quality(self, run_id: str, **values: object) -> dict[str, object]:
        self.calls.append(("drive", run_id, values))
        return {"run_id": run_id, "drive_id": "drive-1"}

    def confirm_fitness(self, run_id: str, **values: object) -> dict[str, object]:
        self.calls.append(("confirm", run_id, values))
        return {"run_id": run_id, "outcome": "UNFIT"}

    def assert_session(self, run_id: str, session_id: str) -> None:
        self.calls.append(("session", run_id, session_id))

    def submit_baseline(self, run_id: str, **values: object) -> dict[str, object]:
        self.calls.append(("submit_baseline", run_id, values))
        return {"artifact": {"id": "BASELINE-1"}, "revision": 2}

    def submit_spec(self, run_id: str, **values: object) -> dict[str, object]:
        self.calls.append(("submit_spec", run_id, values))
        return {"artifact": {"id": "SPEC-1"}, "revision": 2}

    def submit_plan(self, run_id: str, **values: object) -> dict[str, object]:
        self.calls.append(("submit_plan", run_id, values))
        return {"artifact": {"id": "PLAN-1"}, "revision": 2}

    def authorize_tool(
        self,
        run_id: str,
        tool_name: str,
        paths: list[str],
        *,
        call_id: str,
        session_id: str,
        expected_revision: int,
        context_digest: str,
        skill_binding_digest: str,
    ) -> dict[str, object]:
        self.calls.append(
            (
                "authorize",
                run_id,
                tool_name,
                paths,
                call_id,
                session_id,
                expected_revision,
                context_digest,
                skill_binding_digest,
            )
        )
        return {"revision": 2}

    def attach_session(
        self,
        run_id: str,
        session_id: str,
        *,
        expected_revision: int,
        context_digest: str,
        skill_binding_digest: str,
    ) -> object:
        self.calls.append(
            (
                "attach",
                run_id,
                session_id,
                expected_revision,
                context_digest,
                skill_binding_digest,
            )
        )
        return type("Run", (), {"run_id": run_id})()


def test_rpc_surface_contains_only_model_runtime_operations() -> None:
    assert {
        "status",
        "quality_status",
        "drive_quality",
        "confirm_fitness",
        "bind_task",
        "attach_session",
        "submit_baseline",
        "submit_spec",
        "submit_plan",
        "complete_phase",
        "authorize_tool",
        "post_tool",
    } == ALLOWED_OPERATIONS


@pytest.mark.parametrize("operation", ["submit_baseline", "submit_spec", "submit_plan"])
def test_rpc_submits_only_declared_planning_candidates(operation: str) -> None:
    guardian = FakeGuardian()
    body = {"id": "candidate"}
    result = _dispatch(
        guardian,
        {
            "id": 1,
            "op": operation,
            "params": {
                "run_id": "run-1",
                "session_id": "session-1",
                "expected_revision": 1,
                "context_digest": "context-1",
                "skill_binding_digest": "skill-1",
                "body": body,
            },
        },
    )
    assert result["revision"] == 2
    assert guardian.calls[0] == ("session", "run-1", "session-1")
    assert guardian.calls[1][0:2] == (operation, "run-1")


def test_rpc_rejects_legacy_packet_submission_and_model_approval() -> None:
    for operation in ("submit_packet", "approve_plan", "approve_plan_receipt"):
        guardian = FakeGuardian()
        with pytest.raises(GuardError) as caught:
            _dispatch(guardian, {"id": 1, "op": operation, "params": {"run_id": "run-1"}})
        assert caught.value.code == "UNKNOWN_OPERATION"
        assert guardian.calls == []


def test_rpc_quality_status_is_read_only() -> None:
    guardian = FakeGuardian()
    result = _dispatch(
        guardian,
        {"id": 1, "op": "quality_status", "params": {"run_id": "run-1"}},
    )
    assert result == {"run_id": "run-1", "readiness": "NEEDS_PACKET"}
    assert guardian.calls == []


def test_rpc_quality_commands_require_the_existing_session_context() -> None:
    guardian = FakeGuardian()
    result = _dispatch(
        guardian,
        {
            "id": 1,
            "op": "drive_quality",
            "params": {
                "run_id": "run-1",
                "session_id": "session-1",
                "expected_revision": 1,
                "context_digest": "context-1",
                "skill_binding_digest": "skill-1",
                "request_id": "request-1",
            },
        },
    )
    assert result == {"run_id": "run-1", "drive_id": "drive-1"}
    assert guardian.calls[0] == ("session", "run-1", "session-1")
    assert guardian.calls[1][0:2] == ("drive", "run-1")


def test_rpc_requires_the_bound_session_for_tool_authorization() -> None:
    guardian = FakeGuardian()
    result = _dispatch(
        guardian,
        {
            "id": 1,
            "op": "authorize_tool",
            "params": {
                "run_id": "run-1",
                "session_id": "session-1",
                "tool_name": "read",
                "paths": [],
                "call_id": "call-1",
                "expected_revision": 1,
                "context_digest": "context-1",
                "skill_binding_digest": "skill-1",
            },
        },
    )
    assert result == {"revision": 2}
    assert guardian.calls == [
        ("session", "run-1", "session-1"),
        (
            "authorize",
            "run-1",
            "read",
            [],
            "call-1",
            "session-1",
            1,
            "context-1",
            "skill-1",
        ),
    ]


def test_rpc_attaches_a_fresh_session_without_preasserting_it() -> None:
    guardian = FakeGuardian()
    result = _dispatch(
        guardian,
        {
            "id": 1,
            "op": "attach_session",
            "params": {
                "run_id": "run-1",
                "session_id": "session-2",
                "expected_revision": 1,
                "context_digest": "context-1",
                "skill_binding_digest": "skill-1",
            },
        },
    )
    assert result["context_digest"] == "context-1"
    assert guardian.calls == [("attach", "run-1", "session-2", 1, "context-1", "skill-1")]


def test_rpc_rejects_mutations_without_context_binding() -> None:
    with pytest.raises(GuardError) as caught:
        _dispatch(
            FakeGuardian(),
            {
                "id": 1,
                "op": "attach_session",
                "params": {"run_id": "run-1", "session_id": "session-2"},
            },
        )
    assert caught.value.code == "INVALID_REQUEST"
