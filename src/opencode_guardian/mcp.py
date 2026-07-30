from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .errors import GuardError
from .facade import Guardian, project_guard_context
from .persistence import StateStore, default_state_dir
from .persistence.database import select_run
from .quality import project_quality_status

READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
MUTATING = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)


class ReadOnlyRunView:
    """Read projection that opens SQLite in query-only mode."""

    def __init__(self, database: Path, run_id: str) -> None:
        self.database = database.expanduser().resolve(strict=True)
        self.run_id = run_id
        with self._connect() as connection:
            self._run(connection)

    def context(self) -> dict[str, Any]:
        with self._connect() as connection:
            run = self._run(connection)
            phases = connection.execute(
                """
                SELECT phase_id, position, status, change_count, conclusion,
                       requirement_ids_json, acceptance_ids_json,
                       allowed_paths_json, check_ids_json
                FROM phase_executions
                WHERE run_id = ? ORDER BY position
                """,
                (self.run_id,),
            ).fetchall()
            checks = connection.execute(
                "SELECT check_id FROM checks WHERE run_id = ? ORDER BY check_id",
                (self.run_id,),
            ).fetchall()
            artifact = connection.execute(
                """
                SELECT version, digest FROM artifacts
                WHERE run_id = ? AND kind = 'packet' AND digest = ?
                """,
                (self.run_id, run["packet_digest"]),
            ).fetchone()
            artifact_count = connection.execute(
                """
                SELECT COUNT(*) FROM artifacts
                WHERE run_id = ? AND kind = 'packet'
                """,
                (self.run_id,),
            ).fetchone()[0]
            lease_row = connection.execute(
                "SELECT call_id, phase_id FROM write_leases WHERE run_id = ?",
                (self.run_id,),
            ).fetchone()
            lease = None
            if lease_row is not None:
                revision = 0
                for event in connection.execute(
                    """
                    SELECT revision, payload_json FROM events
                    WHERE run_id = ? AND type = 'WRITE_AUTHORIZED'
                    ORDER BY seq DESC
                    """,
                    (self.run_id,),
                ).fetchall():
                    if (
                        json.loads(str(event["payload_json"])).get("call_id")
                        == lease_row["call_id"]
                    ):
                        revision = int(event["revision"])
                        break
                lease = {"phase_id": str(lease_row["phase_id"]), "revision": revision}
            latest = connection.execute(
                """
                SELECT batch_id FROM evidence
                WHERE run_id = ? AND packet_digest = ?
                ORDER BY id DESC LIMIT 1
                """,
                (self.run_id, run["packet_digest"]),
            ).fetchone()
            evidence = (
                connection.execute(
                    """
                    SELECT check_id, exit_code, timed_out, created_at FROM evidence
                    WHERE run_id = ? AND batch_id = ? ORDER BY id
                    """,
                    (self.run_id, latest["batch_id"]),
                ).fetchall()
                if latest is not None
                else []
            )
        base = {
            "run_id": str(run["id"]),
            "project_root": str(run["project_root"]),
            "worktree": str(run["worktree"]),
            "base_sha": str(run["base_sha"]),
            "task": str(run["task"]),
            "stage": str(run["stage"]),
            "revision": int(run["revision"]),
            "packet_version": int(artifact["version"]) if artifact is not None else 0,
            "packet_digest": str(run["packet_digest"]),
            "previous_packet_count": max(0, int(artifact_count) - 1),
            "environment_digest": str(run["environment_digest"]),
            "workspace_digest": str(run["workspace_digest"]),
            "evidence_digest": str(run["evidence_digest"]),
            "active_phase": str(run["active_phase"]),
            "allowed_paths": next(
                (
                    json.loads(str(row["allowed_paths_json"]))
                    for row in phases
                    if str(row["status"]) == "ACTIVE"
                ),
                [],
            ),
            "available_checks": [str(row["check_id"]) for row in checks],
            "evidence": [dict(row) for row in evidence],
            "phases": [
                {
                    "id": str(row["phase_id"]),
                    "position": int(row["position"]),
                    "status": str(row["status"]),
                    "change_count": int(row["change_count"]),
                    "conclusion": str(row["conclusion"]),
                    "requirement_ids": json.loads(str(row["requirement_ids_json"])),
                    "acceptance_ids": json.loads(str(row["acceptance_ids_json"])),
                    "allowed_paths": json.loads(str(row["allowed_paths_json"])),
                    "check_ids": json.loads(str(row["check_ids_json"])),
                }
                for row in phases
            ],
            "blocked": {
                "code": str(run["blocked_code"]),
                "message": str(run["blocked_message"]),
            },
        }
        return project_guard_context(
            base,
            lease=lease,
            evidence=[dict(row) for row in evidence],
        )

    def artifact(self) -> dict[str, Any]:
        with self._connect() as connection:
            run = self._run(connection)
            row = connection.execute(
                """
                SELECT * FROM artifacts
                WHERE run_id = ? AND kind = 'packet' AND digest = ?
                """,
                (self.run_id, run["packet_digest"]),
            ).fetchone()
            if row is None:
                return {"present": False, "history": []}
            body = str(row["body_json"])
            if len(body.encode()) > 512 * 1024:
                raise GuardError("RESULT_TOO_LARGE", "Development packet exceeds MCP limits.")
            revisions = connection.execute(
                """
                SELECT payload_json FROM events
                WHERE run_id = ? AND type = 'PACKET_REVISED'
                ORDER BY seq
                """,
                (self.run_id,),
            ).fetchall()
            history_rows = connection.execute(
                """
                SELECT version, digest, created_at FROM artifacts
                WHERE run_id = ? AND kind = 'packet' AND digest <> ?
                ORDER BY version
                """,
                (self.run_id, run["packet_digest"]),
            ).fetchall()
        retired = {
            int(payload["from_version"]): str(payload["retired_phases_digest"])
            for row_payload in revisions
            for payload in [json.loads(str(row_payload["payload_json"]))]
        }
        result = {
            "present": True,
            "kind": "packet",
            "version": int(row["version"]),
            "digest": str(row["digest"]),
            "body": json.loads(body),
            "created_at": str(row["created_at"]),
            "history": [
                {
                    "version": int(history["version"]),
                    "digest": str(history["digest"]),
                    "created_at": str(history["created_at"]),
                    "retired_phases_digest": retired.get(int(history["version"]), ""),
                }
                for history in history_rows
            ],
        }
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 512 * 1024:
            raise GuardError("RESULT_TOO_LARGE", "Development packet exceeds MCP limits.")
        return result

    def evidence(self) -> dict[str, Any]:
        with self._connect() as connection:
            run = self._run(connection)
            latest = connection.execute(
                """
                SELECT batch_id FROM evidence
                WHERE run_id = ? AND packet_digest = ?
                ORDER BY id DESC LIMIT 1
                """,
                (self.run_id, run["packet_digest"]),
            ).fetchone()
            if latest is None:
                return {"items": []}
            rows = connection.execute(
                """
                SELECT * FROM evidence
                WHERE run_id = ? AND batch_id = ? ORDER BY id
                """,
                (self.run_id, latest["batch_id"]),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["requirement_ids"] = json.loads(item.pop("requirement_ids_json"))
            item["acceptance_ids"] = json.loads(item.pop("acceptance_ids_json"))
            item["timed_out"] = bool(item["timed_out"])
            items.append(item)
        return {"items": items}

    def quality_status(self) -> dict[str, Any]:
        return project_quality_status(self.context())

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"{self.database.as_uri()}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("BEGIN")
        return connection

    def _run(self, connection: sqlite3.Connection) -> sqlite3.Row:
        return select_run(connection, self.run_id)


def build_server(view: ReadOnlyRunView, guardian: Guardian | None = None) -> FastMCP[None]:
    server = FastMCP(
        "OpenCode Guard Authority",
        instructions=(
            "Read-only access to the current Guard context, frozen packet, and evidence."
        ),
    )

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def guard_context() -> dict[str, Any]:
        """Read the current Run stage, active phase, checks, and frozen scope."""
        return view.context()

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def guard_artifact() -> dict[str, Any]:
        """Read the single frozen development packet."""
        return view.artifact()

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def guard_evidence() -> dict[str, Any]:
        """Read the latest trusted verification evidence batch."""
        return view.evidence()

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def guard_quality_status() -> dict[str, Any]:
        """Read the bounded quality readiness projection for the current Run."""
        return view.quality_status()

    if guardian is not None:

        def submit_candidate(
            method: str,
            *,
            body: dict[str, Any],
            expected_revision: int,
            session_id: str,
            context_digest: str,
            skill_binding_digest: str,
        ) -> dict[str, Any]:
            guardian.assert_session(view.run_id, session_id)
            submit = getattr(guardian, method)
            return dict(
                submit(
                    view.run_id,
                    expected_revision=expected_revision,
                    body=body,
                    context_digest=context_digest,
                    skill_binding_digest=skill_binding_digest,
                )
            )

        @server.tool(annotations=MUTATING, structured_output=True)
        def guard_submit_baseline(
            body: dict[str, Any],
            expected_revision: int,
            session_id: str,
            context_digest: str,
            skill_binding_digest: str,
        ) -> dict[str, Any]:
            return submit_candidate(
                "submit_baseline",
                body=body,
                expected_revision=expected_revision,
                session_id=session_id,
                context_digest=context_digest,
                skill_binding_digest=skill_binding_digest,
            )

        @server.tool(annotations=MUTATING, structured_output=True)
        def guard_submit_spec(
            body: dict[str, Any],
            expected_revision: int,
            session_id: str,
            context_digest: str,
            skill_binding_digest: str,
        ) -> dict[str, Any]:
            return submit_candidate(
                "submit_spec",
                body=body,
                expected_revision=expected_revision,
                session_id=session_id,
                context_digest=context_digest,
                skill_binding_digest=skill_binding_digest,
            )

        @server.tool(annotations=MUTATING, structured_output=True)
        def guard_submit_plan(
            body: dict[str, Any],
            expected_revision: int,
            session_id: str,
            context_digest: str,
            skill_binding_digest: str,
        ) -> dict[str, Any]:
            return submit_candidate(
                "submit_plan",
                body=body,
                expected_revision=expected_revision,
                session_id=session_id,
                context_digest=context_digest,
                skill_binding_digest=skill_binding_digest,
            )

    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opencode-guard-mcp")
    parser.add_argument("--database", default="")
    parser.add_argument("--run", default="")
    args = parser.parse_args(argv)
    database = (
        Path(args.database).expanduser()
        if args.database
        else Path(
            os.environ.get(
                "OPENCODE_GUARD_STATE_DIR",
                str(default_state_dir()),
            )
        )
        / "guard.db"
    )
    run_id = args.run or os.environ.get("OPENCODE_GUARD_RUN_ID", "")
    state_store = StateStore(database)
    guardian = Guardian(state_store)
    build_server(ReadOnlyRunView(database, run_id), guardian).run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
