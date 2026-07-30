from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import opencode_guardian.cli as cli
from opencode_guardian.errors import GuardError
from opencode_guardian.facade import Guardian
from opencode_guardian.quality import project_quality_status


@pytest.mark.parametrize(
    ("stage", "readiness"),
    [
        ("PLANNING", "NEEDS_PACKET"),
        ("IMPLEMENTING", "IMPLEMENTING"),
        ("VERIFYING", "VERIFYING"),
        ("REVIEW_REQUIRED", "EXTERNAL_REVIEW"),
        ("ACCEPTED", "ACCEPTED"),
    ],
)
def test_quality_status_projects_each_guard_stage(stage: str, readiness: str) -> None:
    result = project_quality_status(
        {
            "run_id": "run-1",
            "stage": stage,
            "active_phase": "P1",
            "revision": 3,
            "evidence": [
                {"exit_code": 0, "timed_out": False},
                {"exit_code": 1, "timed_out": False},
                {"exit_code": 0, "timed_out": True},
            ],
        }
    )
    assert result == {
        "run_id": "run-1",
        "stage": stage,
        "active_phase": "P1",
        "revision": 3,
        "evidence": {"available": 3, "failed": 2},
        "readiness": readiness,
    }


@pytest.mark.parametrize(
    "context",
    [
        {"run_id": "run-1", "stage": "UNKNOWN", "revision": 0},
        {"run_id": "run-1", "stage": "PLANNING", "revision": -1},
        {"run_id": "run-1", "stage": "PLANNING", "revision": 0, "evidence": [{}]},
    ],
)
def test_quality_status_rejects_malformed_context(context: dict[str, object]) -> None:
    with pytest.raises(GuardError) as caught:
        project_quality_status(context)
    assert caught.value.code == "QUALITY_STATUS_INVALID"


def test_guardian_quality_status_only_projects_status(monkeypatch: pytest.MonkeyPatch) -> None:
    guardian = object.__new__(Guardian)
    context: dict[str, Any] = {
        "run_id": "run-1",
        "stage": "IMPLEMENTING",
        "active_phase": "P1",
        "revision": 4,
        "evidence": [],
    }
    monkeypatch.setattr(guardian, "status", lambda run_id: context)
    assert guardian.quality_status("run-1")["readiness"] == "IMPLEMENTING"


def test_cli_quality_status_routes_only_to_guardian(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    class FakeGuardian:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def quality_status(self, run_id: str) -> dict[str, object]:
            return {"run_id": run_id, "readiness": "NEEDS_PACKET"}

    monkeypatch.setattr(cli, "StateStore", lambda _path: SimpleNamespace())
    monkeypatch.setattr(cli, "WorkspaceManager", lambda _path: SimpleNamespace())
    monkeypatch.setattr(cli, "Guardian", FakeGuardian)
    args = cli._parser().parse_args(
        ["--state-dir", str(tmp_path), "quality-status", "--run", "run-1"]
    )
    assert cli._dispatch(args) == {"run_id": "run-1", "readiness": "NEEDS_PACKET"}
