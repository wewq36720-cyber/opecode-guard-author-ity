from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from pathlib import Path

import anyio
import pytest

import opencode_guardian.mcp as mcp_module
from opencode_guardian.contracts import packet_digest
from opencode_guardian.errors import GuardError
from opencode_guardian.facade import Guardian
from opencode_guardian.mcp import ReadOnlyRunView, build_server
from opencode_guardian.persistence import StateStore


def packet() -> dict[str, object]:
    return {
        "certainty": {"confirmed": True, "unresolved_items": [], "assumptions": []},
        "requirements": [
            {"id": "R1", "statement": "Implement guarded changes.", "acceptance_ids": ["A1"]}
        ],
        "acceptance": [
            {
                "id": "A1",
                "criterion": "Guarded files pass checks.",
                "verification": ["pytest"],
                "required_paths": ["src/app.py"],
            }
        ],
        "constraints": ["Tools outside the allowlist are denied."],
        "non_goals": ["Do not modify external projects."],
        "stop_conditions": ["Trusted verification is unavailable."],
        "architecture": {
            "objective": "Minimal guarded development.",
            "public_interface": "Application",
            "dependency_direction": "adapter -> application -> domain",
            "components": [
                {"name": "Application", "responsibility": "Orchestrate.", "dependencies": []}
            ],
            "trust_boundaries": ["Model input is untrusted."],
            "data_flows": ["Requests enter through the Guard."],
            "concurrency": {
                "ordering": "Run revision.",
                "idempotency": "Call ID.",
                "backpressure": "Bounded requests.",
                "limits": "One MiB message.",
                "failures": "Fail closed.",
                "scaling": "Per Run.",
                "observability": "Event digests.",
            },
        },
        "phases": [
            {
                "id": "P1",
                "goal": "Implement.",
                "requirement_ids": ["R1"],
                "acceptance_ids": ["A1"],
                "allowed_paths": ["src/**"],
                "check_ids": ["pytest"],
            }
        ],
    }


def database_digest(path: Path) -> str:
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        logical = "\n".join(connection.iterdump()).encode()
    return hashlib.sha256(logical).hexdigest()


def test_mcp_exposes_exactly_four_read_only_tools(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-mcp",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    run = store.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="implement",
        session_id="session-1",
    )
    body = packet()
    run = store.submit_packet(
        run.run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )
    before = database_digest(store.database)
    server = build_server(ReadOnlyRunView(store.database, run.run_id), Guardian(store))
    expected = Guardian(store).status(run.run_id)

    async def inspect() -> None:
        tools = await server.list_tools()
        assert sorted(tool.name for tool in tools) == [
            "guard_artifact",
            "guard_context",
            "guard_evidence",
            "guard_quality_status",
            "guard_submit_baseline",
            "guard_submit_plan",
            "guard_submit_spec",
        ]
        annotations = {tool.name: tool.annotations for tool in tools}
        assert all(
            annotations[name] and annotations[name].readOnlyHint
            for name in (
                "guard_artifact",
                "guard_context",
                "guard_evidence",
                "guard_quality_status",
            )
        )
        assert all(
            not annotations[name].readOnlyHint
            for name in (
                "guard_submit_baseline",
                "guard_submit_plan",
                "guard_submit_spec",
            )
        )
        _content, context = await server.call_tool("guard_context", {})
        assert context["run_id"] == run.run_id
        assert context["allowed_paths"] == ["src/**"]
        assert context["context_digest"] == expected["context_digest"]
        assert context["skill_binding"] == expected["skill_binding"]
        _content, quality = await server.call_tool("guard_quality_status", {})
        assert quality == {
            "run_id": run.run_id,
            "stage": "IMPLEMENTING",
            "active_phase": "P1",
            "revision": run.revision,
            "evidence": {"available": 0, "failed": 0},
            "readiness": "IMPLEMENTING",
        }
        encoded = json.dumps(context)
        assert all(
            field not in encoded
            for field in ("session_id", "call_id", "before_files", "declared_paths")
        )

    anyio.run(inspect)
    assert database_digest(store.database) == before


def test_mcp_view_rejects_a_tampered_event_chain(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-mcp-tampered",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    view = ReadOnlyRunView(store.database, run.run_id)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ?",
            ('{"tampered":true}', run.run_id),
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        view.context()

    assert caught.value.code == "EVENT_CHAIN_BROKEN"


def test_mcp_projects_current_packet_and_bounded_history_after_revision(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-mcp-revision",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    run = store.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="revise current packet",
        session_id="session-1",
    )
    first = packet()
    run = store.submit_packet(
        run.run_id,
        expected_revision=run.revision,
        packet=first,
        digest=packet_digest(first),
    )
    candidate = deepcopy(first)
    candidate["constraints"] = ["Updated bounded constraint."]
    candidate_digest = packet_digest(candidate)
    run = store.submit_packet(
        run.run_id,
        expected_revision=run.revision,
        packet=candidate,
        digest=candidate_digest,
    )
    before = database_digest(store.database)
    view = ReadOnlyRunView(store.database, run.run_id)
    context = view.context()
    artifact = view.artifact()
    facade_context = Guardian(store).status(run.run_id)
    assert context["packet_version"] == 2
    assert context["packet_digest"] == candidate_digest
    assert context["previous_packet_count"] == 1
    for field in (
        "packet_version",
        "packet_digest",
        "previous_packet_count",
        "context_digest",
        "skill_binding",
    ):
        assert context[field] == facade_context[field]
    assert artifact["version"] == 2
    assert artifact["body"] == candidate
    assert [item["version"] for item in artifact["history"]] == [1]
    assert "body" not in artifact["history"][0]
    assert view.evidence() == {"items": []}
    assert database_digest(store.database) == before


def test_mcp_artifact_result_size_gate_is_not_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-mcp-size",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    run = store.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="bounded artifact",
        session_id="session-1",
    )
    body = packet()
    run = store.submit_packet(
        run.run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )
    original_json = mcp_module.json

    class OversizedResultJSON:
        loads = staticmethod(original_json.loads)

        @staticmethod
        def dumps(*_args: object, **_kwargs: object) -> str:
            return "x" * (512 * 1024 + 1)

    monkeypatch.setattr(mcp_module, "json", OversizedResultJSON)
    with pytest.raises(GuardError) as caught:
        ReadOnlyRunView(store.database, run.run_id).artifact()
    assert caught.value.code == "RESULT_TOO_LARGE"


def test_mcp_view_rejects_tampered_run_state(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-mcp-state",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    view = ReadOnlyRunView(store.database, run.run_id)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE checks SET definition_json = ? WHERE run_id = ?",
            ('{"id":"pytest","argv":["malicious"]}', run.run_id),
        )
        connection.commit()

    for operation in (view.context, view.artifact, view.evidence):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_mcp_validation_and_context_read_share_one_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-mcp-snapshot",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    view = ReadOnlyRunView(store.database, run.run_id)
    original_select_run = mcp_module.select_run

    def select_then_tamper(
        connection: sqlite3.Connection,
        selected_run_id: str,
        *,
        verify: bool = True,
        verify_state: bool = True,
    ) -> sqlite3.Row:
        row = original_select_run(
            connection,
            selected_run_id,
            verify=verify,
            verify_state=verify_state,
        )
        assert connection.in_transaction
        with sqlite3.connect(store.database) as writer:
            writer.execute(
                "UPDATE checks SET check_id = 'forged' WHERE run_id = ?",
                (run.run_id,),
            )
            writer.commit()
        return row

    monkeypatch.setattr(mcp_module, "select_run", select_then_tamper)

    assert view.context()["available_checks"] == ["pytest"]
