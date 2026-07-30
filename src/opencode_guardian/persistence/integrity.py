from __future__ import annotations

import sqlite3
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Never

from ..contracts import (
    PlanningStep,
    ReviewGate,
    Stage,
    normalize_packet,
    normalize_plan_approval_receipt,
    normalize_planning_artifact,
    packet_digest,
    planning_artifact_digest,
)
from ..errors import GuardError
from ..evidence import VerificationEvidence, evidence_set_digest
from ..integrity import canonical_json, digest_json, load_bounded_json

STATE_BROKEN = "PERSISTED_STATE_BROKEN"


def checks_digest(connection: sqlite3.Connection, run_id: str) -> str:
    entries = []
    for row in connection.execute(
        "SELECT * FROM checks WHERE run_id = ? ORDER BY check_id", (run_id,)
    ).fetchall():
        body = _json(row["definition_json"], "Check definition")
        check_id = str(row["check_id"])
        if (
            not isinstance(body, dict)
            or body.get("id") != check_id
            or digest_json(body) != row["definition_digest"]
        ):
            _broken("Registered check integrity verification failed.")
        entries.append({"id": check_id, "definition": body})
    if not entries:
        _broken("Run has no registered checks.")
    return digest_json(entries)


def verify_persisted_state(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    event_rows: Sequence[Mapping[str, Any]],
) -> None:
    try:
        run_id = str(run["id"])
        events = [_event(row) for row in event_rows]
        check_digest = checks_digest(connection, run_id)
        _verify_run_anchors(run, events, check_digest)
        _verify_participants(connection, run, events)
        packet, phases, artifacts = _verify_packet_and_phases(connection, run, events)
        _verify_planning(connection, run, events)
        _verify_lease(connection, run, events, phases)
        _verify_evidence(connection, run, events, packet, phases, artifacts)
        _verify_quality(connection, run, events)
    except GuardError as exc:
        if exc.code == STATE_BROKEN:
            raise
        raise GuardError(STATE_BROKEN, "Persisted Run state failed integrity checks.") from exc
    except (
        KeyError,
        MemoryError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise GuardError(STATE_BROKEN, "Persisted Run state is malformed.") from exc


def _verify_participants(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
) -> None:
    rows = connection.execute(
        "SELECT * FROM run_sessions WHERE run_id = ? ORDER BY session_id",
        (str(run["id"]),),
    ).fetchall()
    revision = run["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        _broken("Run revision is malformed for participant validation.")
    actual: dict[str, dict[str, Any]] = {}
    for row in rows:
        session_id = row["session_id"]
        if (
            not isinstance(session_id, str)
            or not session_id.strip()
            or session_id != session_id.strip()
            or "\x00" in session_id
            or len(session_id) > 200
        ):
            _broken("Participant session ID is malformed.")
        status = row["status"]
        attached_revision = row["attached_revision"]
        if (
            status not in {"ACTIVE", "REVOKED"}
            or not isinstance(attached_revision, int)
            or isinstance(attached_revision, bool)
            or attached_revision < 0
            or attached_revision > revision
        ):
            _broken("Participant state is malformed.")
        attached_at = _timestamp(row["attached_at"], "Participant attachment time")
        revoked_at = row["revoked_at"]
        if status == "ACTIVE":
            if revoked_at != "":
                _broken("Active participant has a revocation time.")
        else:
            revoked = _timestamp(revoked_at, "Participant revocation time")
            if revoked < attached_at:
                _broken("Participant was revoked before it was attached.")
        actual[session_id] = {
            "status": status,
            "attached_revision": attached_revision,
            "attached_at": str(row["attached_at"]),
            "revoked_at": str(revoked_at),
        }

    legacy_session = str(run["session_id"])
    expected: dict[str, dict[str, Any]] = {}
    task_bound = next((event for event in events if event["type"] == "TASK_BOUND"), None)
    if (
        legacy_session
        and task_bound is not None
        and task_bound["payload"].get("participant_attached") is True
    ):
        expected[legacy_session] = {
            "status": "ACTIVE",
            "attached_revision": task_bound["revision"],
            "attached_at": task_bound["created_at"],
            "revoked_at": "",
        }
    for event in events:
        if event["type"] not in {"SESSION_ATTACHED", "SESSION_REVOKED"}:
            continue
        session_id = event["payload"].get("session_id")
        if not isinstance(session_id, str) or not session_id:
            _broken("Participant event session ID is malformed.")
        if event["type"] == "SESSION_ATTACHED":
            if session_id in expected:
                _broken("Participant has duplicate attachment events.")
            expected[session_id] = {
                "status": "ACTIVE",
                "attached_revision": event["revision"],
                "attached_at": event["created_at"],
                "revoked_at": "",
            }
            continue
        participant = expected.get(session_id)
        if participant is None and session_id == legacy_session and task_bound is not None:
            participant = {
                "status": "ACTIVE",
                "attached_revision": task_bound["revision"],
                "attached_at": task_bound["created_at"],
                "revoked_at": "",
            }
            expected[session_id] = participant
        if participant is None or participant["status"] != "ACTIVE":
            _broken("Participant revocation has no active attachment.")
        participant["status"] = "REVOKED"
        participant["revoked_at"] = event["created_at"]
    if actual != expected:
        _broken("Participant state does not match lifecycle events.")


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        _broken(f"{label} is malformed.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _broken(f"{label} is malformed.")
    if parsed.tzinfo is None:
        _broken(f"{label} is malformed.")
    return parsed


def _verify_run_anchors(
    run: Mapping[str, Any], events: list[dict[str, Any]], check_digest: str
) -> None:
    created = events[0]
    payload = created["payload"]
    initial_workspace = payload.get("workspace_digest")
    expected = {
        "base_sha": str(run["base_sha"]),
        "project_root": str(run["project_root"]),
        "git_common_dir": str(run["git_common_dir"]),
        "worktree": str(run["worktree"]),
        "environment_digest": str(run["environment_digest"]),
        "workspace_digest": initial_workspace,
        "checks_digest": check_digest,
    }
    if (
        created["type"] != "RUN_CREATED"
        or not isinstance(initial_workspace, str)
        or not initial_workspace
        or payload != expected
    ):
        _broken("Run creation anchors do not match current state.")

    workspace_digest = ""
    packet_digest = ""
    evidence_digest = ""
    blocked_code = ""
    blocked_message = ""
    task_digest = ""
    session_id = ""
    for event in events:
        payload = event["payload"]
        event_type = event["type"]
        if event_type == "RUN_CREATED":
            workspace_digest = str(payload["workspace_digest"])
        elif event_type == "TASK_BOUND":
            task_digest = str(payload["task_digest"])
            actor = str(event["actor"])
            session_id = actor.removeprefix("session:") if actor.startswith("session:") else ""
        elif event_type == "PACKET_FROZEN":
            packet_digest = str(payload["digest"])
            evidence_digest = ""
        elif event_type == "PLAN_APPROVAL_RECEIPT_CONSUMED":
            packet_digest = str(payload["packet_digest"])
            evidence_digest = ""
        elif event_type == "PACKET_REVISED":
            packet_digest = str(payload["to_digest"])
            evidence_digest = ""
        elif event_type == "WRITE_RECORDED":
            workspace_digest = str(payload["workspace_digest"])
            evidence_digest = ""
        elif event_type in {"VERIFICATION_PASSED", "VERIFICATION_FAILED"}:
            evidence_digest = str(payload["evidence_digest"])
        elif event_type == "CHANGES_REQUESTED":
            evidence_digest = ""
        elif event_type == "RUN_BLOCKED":
            blocked_code = str(payload["code"])
            blocked_message = str(payload["message"])
        elif event_type == "STARTUP_FAILED":
            blocked_code = "STARTUP_FAILED"
            blocked_message = "Run startup failed before OpenCode became active."

    if (
        packet_digest != str(run["packet_digest"])
        or evidence_digest != str(run["evidence_digest"])
        or workspace_digest != str(run["workspace_digest"])
        or blocked_code != str(run["blocked_code"])
        or blocked_message != str(run["blocked_message"])
    ):
        _broken("Run data anchors do not match their events.")
    if bool(run["task"]) != bool(task_digest) or (
        task_digest and digest_json(str(run["task"])) != task_digest
    ):
        _broken("Run task does not match its binding event.")
    if str(run["session_id"]) != session_id:
        _broken("Run session does not match its binding event.")


def _verify_packet_and_phases(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    run_id = str(run["id"])
    artifact_rows = connection.execute(
        "SELECT * FROM artifacts WHERE run_id = ? ORDER BY kind, version", (run_id,)
    ).fetchall()
    phase_rows = connection.execute(
        "SELECT * FROM phase_executions WHERE run_id = ? ORDER BY position", (run_id,)
    ).fetchall()
    if not run["packet_digest"]:
        if artifact_rows or phase_rows or run["active_phase"]:
            _broken("Unfrozen Run contains packet-derived state.")
        return None, [], []
    if not artifact_rows or any(row["kind"] != "packet" for row in artifact_rows):
        _broken("Run contains an unknown or missing packet artifact.")

    check_ids = {
        str(row["check_id"])
        for row in connection.execute(
            "SELECT check_id FROM checks WHERE run_id = ?", (run_id,)
        ).fetchall()
    }
    artifacts: list[dict[str, Any]] = []
    for expected_version, row in enumerate(artifact_rows, start=1):
        packet = _json(row["body_json"], "Frozen packet")
        if not isinstance(packet, dict):
            _broken("Frozen packet is not an object.")
        version = int(row["version"])
        digest = digest_json(packet)
        if (
            version != expected_version
            or digest != row["digest"]
            or canonical_json(packet) != str(row["body_json"])
        ):
            _broken("Packet artifact version or digest is invalid.")
        if "certainty" in packet and normalize_packet(packet, available_checks=check_ids) != packet:
            _broken("Frozen packet is not canonical.")
        _timestamp(row["created_at"], "Packet creation time")
        artifacts.append(
            {
                "version": version,
                "digest": digest,
                "body": packet,
                "created_at": str(row["created_at"]),
            }
        )
    if len({item["digest"] for item in artifacts}) != len(artifacts):
        _broken("Packet artifact digests are not unique.")

    frozen = [event for event in events if event["type"] == "PACKET_FROZEN"]
    activated = [event for event in events if event["type"] == "PLAN_APPROVAL_RECEIPT_CONSUMED"]
    revised = [event for event in events if event["type"] == "PACKET_REVISED"]
    if len(frozen) + len(activated) != 1 or len(revised) != len(artifacts) - 1:
        _broken("Packet anchors do not match artifact versions.")
    initial = frozen[0] if frozen else activated[0]
    first_payload = initial["payload"]
    expected_phases = [phase["id"] for phase in artifacts[0]["body"]["phases"]]
    if initial["type"] == "PACKET_FROZEN":
        if (
            first_payload.get("digest") != artifacts[0]["digest"]
            or ("version" in first_payload and first_payload.get("version") != 1)
            or first_payload.get("phases") != expected_phases
            or (
                "scope_digest" in first_payload
                and first_payload["scope_digest"]
                != digest_json(_scope_declarations(artifacts[0]["body"]))
            )
        ):
            _broken("Frozen packet anchor is invalid.")
    elif (
        first_payload.get("packet_digest") != artifacts[0]["digest"]
        or first_payload.get("version") != 1
        or first_payload.get("phases") != expected_phases
        or first_payload.get("active_phase") != expected_phases[0]
        or first_payload.get("scope_digest")
        != digest_json(_scope_declarations(artifacts[0]["body"]))
    ):
        _broken("Approved PLAN packet anchor is invalid.")

    anchors = [initial, *revised]
    anchors.sort(key=lambda event: event["seq"])
    if [event["type"] for event in anchors] != [initial["type"]] + ["PACKET_REVISED"] * (
        len(artifacts) - 1
    ):
        _broken("Packet anchors are out of order.")
    consumed_approvals: set[int] = set()
    for index, event in enumerate(revised, start=1):
        previous = artifacts[index - 1]
        current = artifacts[index]
        payload = event["payload"]
        added, removed = _scope_delta(previous["body"], current["body"])
        snapshot = payload.get("retired_phases")
        if not isinstance(snapshot, list) or payload != {
            "from_version": previous["version"],
            "to_version": current["version"],
            "from_digest": previous["digest"],
            "to_digest": current["digest"],
            "retired_active_phase": payload.get("retired_active_phase"),
            "retired_phases": snapshot,
            "retired_phases_digest": digest_json(snapshot),
            "phases": [phase["id"] for phase in current["body"]["phases"]],
            "scope_digest": digest_json(_scope_declarations(current["body"])),
            "added_paths": added,
            "removed_paths": removed,
            "approval_event_seq": payload.get("approval_event_seq"),
        }:
            _broken("Packet revision anchor is malformed.")
        previous_anchor_seq = anchors[index - 1]["seq"]
        interval = [item for item in events if previous_anchor_seq < item["seq"] < event["seq"]]
        _verify_retired_snapshot(previous, snapshot, payload, interval)
        approval_seq = payload.get("approval_event_seq")
        if added:
            if not isinstance(approval_seq, int) or isinstance(approval_seq, bool):
                _broken("Expanded packet scope has no approval event.")
            if approval_seq in consumed_approvals:
                _broken("Packet scope approval was consumed more than once.")
            approval = next(
                (item for item in events if item["seq"] == approval_seq),
                None,
            )
            if (
                approval is None
                or approval["type"] != "PLAN_SCOPE_APPROVED"
                or approval["seq"] >= event["seq"]
                or approval["actor"] != "authority"
                or approval["payload"]
                != {
                    "base_packet_digest": previous["digest"],
                    "candidate_packet_digest": current["digest"],
                    "added_paths": added,
                    "added_paths_digest": digest_json(added),
                    "approved_by": approval["payload"].get("approved_by"),
                }
            ):
                _broken("Packet scope approval does not match its revision.")
            approved_by = approval["payload"].get("approved_by")
            if (
                not isinstance(approved_by, str)
                or not approved_by.strip()
                or len(approved_by) > 200
            ):
                _broken("Packet scope approver is malformed.")
            consumed_approvals.add(approval_seq)
        elif approval_seq is not None:
            _broken("Non-expanding packet revision references an approval.")

    current_artifact = artifacts[-1]
    if current_artifact["digest"] != run["packet_digest"]:
        _broken("Current packet pointer does not reference the latest artifact.")
    _verify_packet_event_intervals(events, anchors, artifacts)

    packet = current_artifact["body"]
    packet_phases = packet["phases"]
    if len(phase_rows) != len(packet_phases):
        _broken("Frozen phase count does not match the packet.")

    current_anchor_seq = anchors[-1]["seq"]
    expected_snapshot = _replay_phase_snapshot(
        current_artifact,
        [event for event in events if event["seq"] > current_anchor_seq],
    )
    active_id = str(run["active_phase"])
    stage = str(run["stage"])
    replayed_active = [
        str(phase["id"]) for phase in expected_snapshot if phase["status"] == "ACTIVE"
    ]
    if stage == Stage.IMPLEMENTING.value:
        if replayed_active != [active_id] or not active_id:
            _broken("Implementing Run has no packet-defined active phase.")
    elif (
        active_id
        or replayed_active
        or any(phase["status"] != "COMPLETED" for phase in expected_snapshot)
    ):
        _broken("Non-implementing Run has an invalid phase projection.")

    result = []
    for row, phase, expected in zip(phase_rows, packet_phases, expected_snapshot, strict=True):
        actual = {
            "id": str(row["phase_id"]),
            "position": int(row["position"]),
            "status": str(row["status"]),
            "requirement_ids": _json(row["requirement_ids_json"], "Phase requirements"),
            "acceptance_ids": _json(row["acceptance_ids_json"], "Phase acceptance"),
            "allowed_paths": _json(row["allowed_paths_json"], "Phase paths"),
            "check_ids": _json(row["check_ids_json"], "Phase checks"),
            "change_count": int(row["change_count"]),
            "conclusion": str(row["conclusion"]),
            "updated_at": str(row["updated_at"]),
        }
        if actual != expected:
            _broken("Phase execution state does not match lifecycle events.")
        result.append({**phase, "status": expected["status"]})
    return packet, result, artifacts


def _verify_planning(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
) -> None:
    run_id = str(run["id"])
    artifact_rows = connection.execute(
        "SELECT * FROM planning_artifacts WHERE run_id = ? ORDER BY created_at, artifact_id",
        (run_id,),
    ).fetchall()
    receipt_rows = connection.execute(
        "SELECT * FROM plan_approval_receipts WHERE run_id = ? ORDER BY approval_id", (run_id,)
    ).fetchall()
    state_rows = connection.execute(
        "SELECT * FROM planning_states WHERE run_id = ?", (run_id,)
    ).fetchall()
    planning_events = [
        event
        for event in events
        if event["type"]
        in {
            "PLANNING_ARTIFACT_STORED",
            "PLAN_APPROVAL_RECEIPT_RECORDED",
            "PLAN_APPROVAL_RECEIPT_CONSUMED",
        }
    ]
    if not artifact_rows and not receipt_rows and not planning_events:
        if not state_rows:
            return
        if len(state_rows) != 1:
            _broken("Run has duplicate planning state rows.")
        state = state_rows[0]
        if (
            state["planning_step"] != PlanningStep.COMPATIBILITY_READ_ONLY.value
            or state["review_gate"] != ""
        ):
            _broken("Planning state has no persisted authority.")
        _timestamp(state["updated_at"], "Compatibility planning state time")
        return
    if len(state_rows) != 1:
        _broken("Planning facts have no unique planning state.")

    artifact_events = [
        event for event in planning_events if event["type"] == "PLANNING_ARTIFACT_STORED"
    ]
    if len(artifact_rows) != len(artifact_events):
        _broken("Planning artifacts do not match event anchors.")
    artifact_by_id: dict[str, dict[str, Any]] = {}
    expected_steps = {
        "BASELINE": (PlanningStep.BASELINE_REVIEW_REQUIRED.value, ReviewGate.BASELINE.value),
        "SPEC": (PlanningStep.SPEC_REVIEW_REQUIRED.value, ReviewGate.SPEC.value),
        "PLAN": (PlanningStep.PLAN_REVIEW_REQUIRED.value, ReviewGate.PLAN.value),
    }
    for row in artifact_rows:
        body = _json(row["body_json"], "Planning artifact")
        if not isinstance(body, dict):
            _broken("Planning artifact is not an object.")
        artifact = normalize_planning_artifact(body)
        digest = planning_artifact_digest(artifact)
        expected_step, expected_gate = expected_steps[artifact["kind"]]
        if (
            canonical_json(artifact) != row["body_json"]
            or digest != row["digest"]
            or artifact["id"] != row["artifact_id"]
            or artifact["base_sha"] != row["base_sha"]
            or artifact["workspace_digest"] != row["workspace_digest"]
            or int(row["revision"]) < 0
            or row["planning_step"] != expected_step
            or row["review_gate"] != expected_gate
        ):
            _broken("Planning artifact integrity verification failed.")
        _timestamp(row["created_at"], "Planning artifact creation time")
        if artifact["id"] in artifact_by_id:
            _broken("Planning artifact ID is not unique.")
        artifact_by_id[artifact["id"]] = {"artifact": artifact, "digest": digest, "row": row}

    candidate_rows = connection.execute(
        "SELECT * FROM plan_candidates WHERE run_id = ? ORDER BY artifact_id", (run_id,)
    ).fetchall()
    candidates: dict[str, dict[str, Any]] = {}
    registered_checks = {
        str(row["check_id"])
        for row in connection.execute("SELECT check_id FROM checks WHERE run_id = ?", (run_id,))
    }
    for row in candidate_rows:
        artifact_id = str(row["artifact_id"])
        bound_artifact = artifact_by_id.get(artifact_id)
        try:
            packet_body = _json(row["packet_json"], "PLAN candidate packet")
            packet = normalize_packet(packet_body, available_checks=registered_checks)
        except GuardError as exc:
            raise GuardError(STATE_BROKEN, "PLAN candidate packet is invalid.") from exc
        if (
            artifact_id in candidates
            or bound_artifact is None
            or bound_artifact["artifact"]["kind"] != "PLAN"
            or row["artifact_digest"] != bound_artifact["digest"]
            or int(row["revision"]) != int(bound_artifact["row"]["revision"])
            or canonical_json(packet) != row["packet_json"]
            or packet_digest(packet) != row["packet_digest"]
            or bound_artifact["artifact"].get("implementation")
            != {
                "packet": packet,
                "phases": packet["phases"],
            }
        ):
            _broken("PLAN candidate binding is invalid.")
        candidates[artifact_id] = {"packet": packet, "row": row, "artifact": bound_artifact}

    anchored_artifacts: set[str] = set()
    for event in artifact_events:
        payload = event["payload"]
        artifact_id = payload.get("artifact_id")
        stored = artifact_by_id.get(artifact_id) if isinstance(artifact_id, str) else None
        if (
            stored is None
            or event["actor"] != "model"
            or int(event["revision"]) != int(stored["row"]["revision"]) + 1
            or payload
            != {
                "artifact_id": artifact_id,
                "kind": stored["artifact"]["kind"],
                "digest": stored["digest"],
                "planning_step": stored["row"]["planning_step"],
                "review_gate": stored["row"]["review_gate"],
                "consumed_review_id": payload.get("consumed_review_id", ""),
            }
            or artifact_id in anchored_artifacts
        ):
            _broken("Planning artifact event anchor is invalid.")
        anchored_artifacts.add(artifact_id)
    if set(artifact_by_id) != anchored_artifacts:
        _broken("Planning artifact events do not cover persisted artifacts.")

    receipt_events = [
        event for event in planning_events if event["type"] == "PLAN_APPROVAL_RECEIPT_RECORDED"
    ]
    if len(receipt_rows) != len(receipt_events):
        _broken("Approval receipts do not match event anchors.")
    receipts: dict[str, dict[str, Any]] = {}
    nonces: set[str] = set()
    for row in receipt_rows:
        receipt = normalize_plan_approval_receipt(
            {
                key: row[key]
                for key in (
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
            }
        )
        bound_artifact = artifact_by_id.get(receipt["artifact_id"])
        if (
            receipt["run_id"] != run_id
            or receipt["base_sha"] != run["base_sha"]
            or bound_artifact is None
            or bound_artifact["artifact"]["kind"] != "PLAN"
            or receipt["artifact_digest"] != bound_artifact["digest"]
            or receipt["nonce"] in nonces
            or receipt["artifact_id"] not in candidates
            or candidates[receipt["artifact_id"]]["row"]["artifact_digest"]
            != receipt["artifact_digest"]
        ):
            _broken("Plan approval receipt binding is invalid.")
        if row["consumed_at"]:
            _timestamp(row["consumed_at"], "Approval receipt consumption time")
        receipts[receipt["approval_id"]] = {"receipt": receipt, "row": row}
        nonces.add(receipt["nonce"])

    anchored_receipts: set[str] = set()
    for event in receipt_events:
        approval_id = event["payload"].get("approval_id")
        stored = receipts.get(approval_id) if isinstance(approval_id, str) else None
        if (
            stored is None
            or event["actor"] != "authority"
            or event["payload"] != stored["receipt"]
            or int(event["revision"]) != int(stored["receipt"]["revision"]) + 1
            or approval_id in anchored_receipts
        ):
            _broken("Plan approval receipt event anchor is invalid.")
        anchored_receipts.add(approval_id)
    if set(receipts) != anchored_receipts:
        _broken("Approval receipt events do not cover persisted receipts.")

    consumed_events = [
        event for event in planning_events if event["type"] == "PLAN_APPROVAL_RECEIPT_CONSUMED"
    ]
    consumed_ids: set[str] = set()
    for event in consumed_events:
        approval_id = event["payload"].get("approval_id")
        stored = receipts.get(approval_id) if isinstance(approval_id, str) else None
        if (
            stored is None
            or not stored["row"]["consumed_at"]
            or event["actor"] != "authority"
            or not _activation_payload_matches(event["payload"], stored["receipt"], candidates)
            or approval_id in consumed_ids
        ):
            _broken("Plan approval receipt consumption anchor is invalid.")
        consumed_ids.add(approval_id)
    persisted_consumed = {
        approval_id for approval_id, stored in receipts.items() if stored["row"]["consumed_at"]
    }
    if consumed_ids != persisted_consumed:
        _broken("Plan approval receipt consumption does not match persisted state.")

    for candidate in candidates.values():
        bound_receipts = [
            stored
            for stored in receipts.values()
            if stored["receipt"]["artifact_id"] == candidate["row"]["artifact_id"]
            and stored["receipt"]["artifact_digest"] == candidate["row"]["artifact_digest"]
        ]
        if len(bound_receipts) > 1:
            _broken("PLAN candidate has multiple approval receipts.")
        if not bound_receipts:
            if run["stage"] != Stage.PLANNING.value or run["packet_digest"] or run["active_phase"]:
                _broken("Unapproved PLAN candidate changed Run execution state.")
            continue
        receipt = bound_receipts[0]
        if not receipt["row"]["consumed_at"]:
            if run["stage"] != Stage.PLANNING.value or run["packet_digest"] or run["active_phase"]:
                _broken("Unconsumed PLAN receipt changed Run execution state.")
            continue
        _verify_candidate_materialization(connection, run, candidate)

    state = state_rows[0]
    if state["planning_step"] == PlanningStep.COMPATIBILITY_READ_ONLY.value:
        _broken("Planning facts cannot coexist with compatibility read-only state.")
    latest_artifact = max(artifact_events, key=lambda event: int(event["seq"]))
    expected_step = latest_artifact["payload"]["planning_step"]
    expected_gate = latest_artifact["payload"]["review_gate"]
    if consumed_events:
        latest_consumption = max(consumed_events, key=lambda event: int(event["seq"]))
        if int(latest_consumption["seq"]) > int(latest_artifact["seq"]):
            expected_step, expected_gate = PlanningStep.PLAN_APPROVED.value, ""
    if state["planning_step"] != expected_step or state["review_gate"] != expected_gate:
        _broken("Planning state does not match persisted artifact and approval facts.")
    _timestamp(state["updated_at"], "Planning state update time")


def _activation_payload_matches(
    payload: Any,
    receipt: Mapping[str, Any],
    candidates: Mapping[str, Mapping[str, Any]],
) -> bool:
    if not isinstance(payload, dict):
        return False
    candidate = candidates.get(str(receipt["artifact_id"]))
    if candidate is None or candidate["row"]["artifact_digest"] != receipt["artifact_digest"]:
        return False
    packet = candidate["packet"]
    return payload == {
        "approval_id": receipt["approval_id"],
        "nonce": receipt["nonce"],
        "artifact_digest": receipt["artifact_digest"],
        "packet_digest": candidate["row"]["packet_digest"],
        "version": 1,
        "phases": [phase["id"] for phase in packet["phases"]],
        "active_phase": packet["phases"][0]["id"],
        "scope_digest": digest_json(_scope_declarations(packet)),
    }


def _verify_candidate_materialization(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> None:
    packet = candidate["packet"]
    digest = candidate["row"]["packet_digest"]
    artifact_rows = connection.execute(
        "SELECT * FROM artifacts WHERE run_id = ? AND kind = 'packet' AND version = 1",
        (run["id"],),
    ).fetchall()
    if (
        len(artifact_rows) != 1
        or artifact_rows[0]["digest"] != digest
        or artifact_rows[0]["body_json"] != canonical_json(packet)
    ):
        _broken("Approved PLAN packet artifact is not materialized canonically.")


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


def _verify_retired_snapshot(
    artifact: dict[str, Any],
    snapshot: list[Any],
    payload: dict[str, Any],
    events: list[dict[str, Any]],
) -> None:
    expected = _replay_phase_snapshot(artifact, events)
    if snapshot != expected:
        _broken("Retired phase snapshot does not match its event interval.")
    active = [str(item["id"]) for item in expected if item["status"] == "ACTIVE"]
    retired_active = payload.get("retired_active_phase")
    if active != ([retired_active] if retired_active else []):
        _broken("Retired active phase does not match its snapshot.")


def _replay_phase_snapshot(
    artifact: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    created_at = str(artifact["created_at"])
    _timestamp(created_at, "Packet creation time")
    result = [
        {
            "id": phase["id"],
            "position": position,
            "status": "ACTIVE" if position == 0 else "PENDING",
            "requirement_ids": phase["requirement_ids"],
            "acceptance_ids": phase["acceptance_ids"],
            "allowed_paths": phase["allowed_paths"],
            "check_ids": phase["check_ids"],
            "change_count": 0,
            "conclusion": "",
            "updated_at": created_at,
        }
        for position, phase in enumerate(artifact["body"]["phases"])
    ]
    by_id = {str(phase["id"]): phase for phase in result}
    for event in events:
        event_type = str(event["type"])
        payload = event["payload"]
        event_time = str(event["created_at"])
        _timestamp(event_time, "Phase lifecycle event time")
        if event_type == "WRITE_RECORDED":
            phase = by_id.get(str(payload.get("phase", "")))
            paths = payload.get("paths")
            if phase is None or phase["status"] != "ACTIVE" or not isinstance(paths, list):
                _broken("Recorded write does not match an active packet phase.")
            phase["change_count"] += len(paths)
            phase["updated_at"] = event_time
        elif event_type == "PHASE_COMPLETED":
            phase = by_id.get(str(payload.get("phase_id", "")))
            if phase is None or phase["status"] != "ACTIVE":
                _broken("Completed phase was not active in its packet interval.")
            position = int(phase["position"])
            next_phase = result[position + 1] if position + 1 < len(result) else None
            next_id = str(next_phase["id"]) if next_phase is not None else ""
            rationale = payload.get("rationale")
            outcome = payload.get("outcome")
            if (
                payload.get("next_phase") != next_id
                or not isinstance(rationale, str)
                or not rationale.strip()
                or outcome not in {"changed", "no-change"}
                or (outcome == "changed" and phase["change_count"] == 0)
            ):
                _broken("Completed phase event is malformed.")
            phase["status"] = "COMPLETED"
            phase["conclusion"] = rationale
            phase["updated_at"] = event_time
            if next_phase is not None:
                if next_phase["status"] != "PENDING":
                    _broken("Completed phase activates an invalid successor.")
                next_phase["status"] = "ACTIVE"
                next_phase["updated_at"] = event_time
        elif event_type in {"VERIFICATION_FAILED", "CHANGES_REQUESTED"}:
            if not result or any(phase["status"] != "COMPLETED" for phase in result):
                _broken("Review or verification reopened an incomplete packet.")
            result[-1]["status"] = "ACTIVE"
            result[-1]["conclusion"] = ""
            result[-1]["updated_at"] = event_time
    return result


def _verify_packet_event_intervals(
    events: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> None:
    bound_types = {
        "WRITE_AUTHORIZED",
        "WRITE_RECORDED",
        "WRITE_RECOVERED",
        "PHASE_COMPLETED",
        "CHANGES_REQUESTED",
        "VERIFICATION_PASSED",
        "VERIFICATION_FAILED",
        "RUN_ACCEPTED",
    }
    legacy = len(artifacts) == 1 and "version" not in anchors[0]["payload"]
    anchor_index = 0
    for event in events:
        while anchor_index + 1 < len(anchors) and event["seq"] >= anchors[anchor_index + 1]["seq"]:
            anchor_index += 1
        if event["type"] not in bound_types or event["seq"] <= anchors[anchor_index]["seq"]:
            continue
        actual = event["payload"].get("packet_digest")
        if actual is None and legacy:
            continue
        if actual != artifacts[anchor_index]["digest"]:
            _broken("Lifecycle event is bound to the wrong packet version.")


def _verify_lease(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
    phases: list[dict[str, Any]],
) -> None:
    open_events: dict[str, dict[str, Any]] = {}
    for event in events:
        payload = event["payload"]
        if event["type"] == "WRITE_AUTHORIZED":
            open_events[str(payload["call_id"])] = event
        elif event["type"] in {"WRITE_RECORDED", "WRITE_RECOVERED"}:
            open_events.pop(str(payload["call_id"]), None)
    rows = connection.execute(
        "SELECT * FROM write_leases WHERE run_id = ?", (str(run["id"]),)
    ).fetchall()
    if len(rows) != len(open_events) or len(rows) > 1:
        _broken("Active write lease does not match authorization events.")
    if not rows:
        return
    row = rows[0]
    phase = next((item for item in phases if item["id"] == row["phase_id"]), None)
    lease = {
        "call_id": str(row["call_id"]),
        "tool_name": str(row["tool_name"]),
        "phase_id": str(row["phase_id"]),
        "requirement_ids": _json(row["requirement_ids_json"], "Lease requirements"),
        "acceptance_ids": _json(row["acceptance_ids_json"], "Lease acceptance"),
        "declared_paths": _json(row["declared_paths_json"], "Lease paths"),
        "before_digest": str(row["before_digest"]),
        "before_files": _json(row["before_files_json"], "Lease files"),
        "created_at": str(row["created_at"]),
    }
    authorized_event = open_events.get(lease["call_id"])
    authorized_payload = authorized_event["payload"] if authorized_event is not None else None
    if (
        authorized_event is not None
        and authorized_payload is not None
        and authorized_payload.get("participant_bound") is True
    ):
        actor = str(authorized_event["actor"])
        if not actor.startswith("session:") or not actor.removeprefix("session:"):
            _broken("Bound write lease has no participant actor.")
        lease["session_id"] = actor.removeprefix("session:")
    if (
        phase is None
        or phase["status"] != "ACTIVE"
        or lease["requirement_ids"] != phase["requirement_ids"]
        or lease["acceptance_ids"] != phase["acceptance_ids"]
        or authorized_event is None
        or authorized_payload is None
        or authorized_payload.get("lease_digest") != digest_json(lease)
    ):
        _broken("Active write lease integrity verification failed.")


def _verify_quality(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
) -> None:
    run_id = str(run["id"])
    by_seq = {event["seq"]: event for event in events}
    drives = connection.execute(
        "SELECT * FROM quality_drives WHERE run_id = ? ORDER BY request_id", (run_id,)
    ).fetchall()
    drive_ids: set[str] = set()
    drive_events: set[int] = set()
    for row in drives:
        result = _json(row["result_json"], "Quality drive result")
        request_id, drive_id = str(row["request_id"]), str(row["drive_id"])
        event_seq = int(row["event_seq"])
        if (
            not isinstance(result, dict)
            or canonical_json(result) != row["result_json"]
            or digest_json(result) != row["result_digest"]
            or not request_id
            or not drive_id
            or drive_id in drive_ids
            or event_seq in drive_events
        ):
            _broken("Quality drive row is malformed.")
        event = by_seq.get(event_seq)
        if (
            event is None
            or event["type"] != "QUALITY_DRIVEN"
            or event["payload"]
            != {
                "request_id": request_id,
                "drive_id": drive_id,
                "result_digest": str(row["result_digest"]),
            }
        ):
            _broken("Quality drive does not match its event anchor.")
        drive_ids.add(drive_id)
        drive_events.add(event_seq)
    if {event["seq"] for event in events if event["type"] == "QUALITY_DRIVEN"} != drive_events:
        _broken("Quality drive events do not match persisted drives.")

    confirmations = connection.execute(
        "SELECT * FROM quality_confirmations WHERE run_id = ? ORDER BY request_id", (run_id,)
    ).fetchall()
    confirmation_events: set[int] = set()
    confirmation_ids: set[str] = set()
    for row in confirmations:
        request_id = str(row["request_id"])
        confirmation_id = str(row["confirmation_id"])
        drive_id = str(row["drive_id"])
        outcome = str(row["outcome"])
        event_seq = int(row["event_seq"])
        if (
            not request_id
            or not confirmation_id
            or confirmation_id in confirmation_ids
            or drive_id not in drive_ids
            or outcome not in {"FIT", "UNFIT"}
            or event_seq in confirmation_events
        ):
            _broken("Quality confirmation row is malformed.")
        event = by_seq.get(event_seq)
        if (
            event is None
            or event["type"] != "QUALITY_FITNESS_CONFIRMED"
            or event["payload"]
            != {
                "request_id": request_id,
                "confirmation_id": confirmation_id,
                "drive_id": drive_id,
                "outcome": outcome,
            }
        ):
            _broken("Quality confirmation does not match its event anchor.")
        confirmation_ids.add(confirmation_id)
        confirmation_events.add(event_seq)
    if {
        event["seq"] for event in events if event["type"] == "QUALITY_FITNESS_CONFIRMED"
    } != confirmation_events:
        _broken("Quality confirmation events do not match persisted facts.")


def _verify_evidence(
    connection: sqlite3.Connection,
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
    packet: dict[str, Any] | None,
    phases: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> None:
    rows = connection.execute(
        "SELECT * FROM evidence WHERE run_id = ? ORDER BY id", (str(run["id"]),)
    ).fetchall()
    batches: defaultdict[str, list[Any]] = defaultdict(list)
    for row in rows:
        batches[str(row["batch_id"])].append(row)
    event_batches: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["type"] not in {"VERIFICATION_PASSED", "VERIFICATION_FAILED"}:
            continue
        batch_id = str(event["payload"]["batch_id"])
        if batch_id in event_batches:
            _broken("Evidence batch has duplicate verification events.")
        event_batches[batch_id] = event
    if set(batches) != set(event_batches):
        _broken("Evidence batches do not match verification events.")

    batch_digests: dict[str, str] = {}
    batch_passed: dict[str, bool] = {}
    batch_packet_digests: dict[str, str] = {}
    artifact_by_digest = {item["digest"]: item for item in artifacts}
    for batch_id, batch_rows in batches.items():
        evidence = [_evidence(row) for row in batch_rows]
        if len({item.check_id for item in evidence}) != len(evidence):
            _broken("Evidence batch contains duplicate checks.")
        digest = evidence_set_digest(evidence)
        previews = {str(row["check_id"]): str(row["output_preview"]) for row in batch_rows}
        event = event_batches[batch_id]
        packet_digests = {str(row["packet_digest"]) for row in batch_rows}
        workspace_digests = {str(row["workspace_digest"]) for row in batch_rows}
        if len(packet_digests) != 1 or len(workspace_digests) != 1:
            _broken("Evidence batch anchors are inconsistent.")
        packet_digest = next(iter(packet_digests))
        artifact = artifact_by_digest.get(packet_digest)
        if artifact is None:
            _broken("Evidence batch references an unknown packet.")
        if (
            any(row["set_digest"] != digest for row in batch_rows)
            or event["payload"].get("evidence_digest") != digest
            or event["payload"].get("previews_digest") != digest_json(previews)
            or (event["type"] == "VERIFICATION_PASSED") != all(item.passed for item in evidence)
            or event["payload"].get("packet_digest", packet_digest) != packet_digest
        ):
            _broken("Evidence batch integrity verification failed.")
        artifact_phases = artifact["body"]["phases"]
        required = sorted({check for phase in artifact_phases for check in phase["check_ids"]})
        if sorted(str(row["check_id"]) for row in batch_rows) != required:
            _broken("Evidence batch does not exactly cover packet checks.")
        for row in batch_rows:
            check_id = str(row["check_id"])
            expected_requirements = sorted(
                {
                    item
                    for phase in artifact_phases
                    if check_id in phase["check_ids"]
                    for item in phase["requirement_ids"]
                }
            )
            expected_acceptance = sorted(
                {
                    item
                    for phase in artifact_phases
                    if check_id in phase["check_ids"]
                    for item in phase["acceptance_ids"]
                }
            )
            if (
                str(row["base_sha"]) != run["base_sha"]
                or _json(row["requirement_ids_json"], "Evidence requirements")
                != expected_requirements
                or _json(row["acceptance_ids_json"], "Evidence acceptance") != expected_acceptance
            ):
                _broken("Evidence batch does not match its packet anchors.")
        batch_digests[batch_id] = digest
        batch_passed[batch_id] = all(item.passed for item in evidence)
        batch_packet_digests[batch_id] = packet_digest

    current_digest = str(run["evidence_digest"])
    if not current_digest:
        if str(run["stage"]) in {Stage.REVIEW_REQUIRED.value, Stage.ACCEPTED.value}:
            _broken("Reviewable Run has no current evidence.")
        return
    current_event = next(
        (
            event
            for event in reversed(events)
            if event["type"] in {"VERIFICATION_PASSED", "VERIFICATION_FAILED"}
            and event["payload"].get("packet_digest", run["packet_digest"]) == run["packet_digest"]
        ),
        None,
    )
    if current_event is None:
        _broken("Run evidence anchor has no verification event.")
    batch_id = str(current_event["payload"]["batch_id"])
    if (
        batch_digests.get(batch_id) != current_digest
        or batch_packet_digests.get(batch_id) != run["packet_digest"]
        or packet is None
    ):
        _broken("Current evidence digest does not match its batch.")
    required = sorted({check for phase in phases for check in phase["check_ids"]})
    batch_rows = batches[batch_id]
    if sorted(str(row["check_id"]) for row in batch_rows) != required:
        _broken("Current evidence does not exactly cover required checks.")
    for row in batch_rows:
        check_id = str(row["check_id"])
        expected_requirements = sorted(
            {
                item
                for phase in phases
                if check_id in phase["check_ids"]
                for item in phase["requirement_ids"]
            }
        )
        expected_acceptance = sorted(
            {
                item
                for phase in phases
                if check_id in phase["check_ids"]
                for item in phase["acceptance_ids"]
            }
        )
        if (
            str(row["base_sha"]) != run["base_sha"]
            or str(row["packet_digest"]) != run["packet_digest"]
            or str(row["workspace_digest"]) != run["workspace_digest"]
            or _json(row["requirement_ids_json"], "Evidence requirements") != expected_requirements
            or _json(row["acceptance_ids_json"], "Evidence acceptance") != expected_acceptance
        ):
            _broken("Current evidence does not match frozen Run anchors.")
    reviewable = str(run["stage"]) in {Stage.REVIEW_REQUIRED.value, Stage.ACCEPTED.value}
    if reviewable and not batch_passed[batch_id]:
        _broken("Reviewable Run evidence is not passing.")
    accepted = [event for event in events if event["type"] == "RUN_ACCEPTED"]
    if str(run["stage"]) == Stage.ACCEPTED.value:
        if len(accepted) != 1 or accepted[0]["payload"] != {
            "packet_digest": str(run["packet_digest"]),
            "workspace_digest": str(run["workspace_digest"]),
            "evidence_digest": current_digest,
        }:
            _broken("Accepted Run is not bound to current packet, workspace, and evidence.")
    elif accepted:
        _broken("Non-accepted Run contains an acceptance event.")


def _evidence(row: Mapping[str, Any]) -> VerificationEvidence:
    requirements = _json(row["requirement_ids_json"], "Evidence requirements")
    acceptance = _json(row["acceptance_ids_json"], "Evidence acceptance")
    if not isinstance(requirements, list) or not isinstance(acceptance, list):
        _broken("Evidence mappings are malformed.")
    return VerificationEvidence(
        run_id=str(row["run_id"]),
        check_id=str(row["check_id"]),
        requirement_ids=tuple(str(item) for item in requirements),
        acceptance_ids=tuple(str(item) for item in acceptance),
        base_sha=str(row["base_sha"]),
        artifact_set_digest=str(row["packet_digest"]),
        workspace_digest=str(row["workspace_digest"]),
        command_digest=str(row["command_digest"]),
        image_digest=str(row["image_digest"]),
        output_digest=str(row["output_digest"]),
        exit_code=int(row["exit_code"]),
        timed_out=bool(row["timed_out"]),
        duration_ms=int(row["duration_ms"]),
    )


def _event(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = load_bounded_json(
        row["payload_json"], code="EVENT_CHAIN_BROKEN", label="Event payload"
    )
    if not isinstance(payload, dict):
        _broken("Event payload is not an object.")
    return {
        "seq": int(row["seq"]),
        "type": str(row["type"]),
        "actor": str(row["actor"]),
        "payload": payload,
        "revision": int(row["revision"]),
        "before_stage": str(row["before_stage"]),
        "after_stage": str(row["after_stage"]),
        "created_at": str(row["created_at"]),
    }


def _json(value: Any, label: str) -> Any:
    return load_bounded_json(value, code=STATE_BROKEN, label=label)


def _broken(message: str) -> Never:
    raise GuardError(STATE_BROKEN, message)
