from __future__ import annotations

import json
from typing import Any

from ..contracts import validate_id
from ..errors import GuardError
from ..integrity import canonical_json, digest_json
from .database import Database, append_event, check_revision, select_run, utc_now


class QualityRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def drive(
        self,
        run_id: str,
        *,
        expected_revision: int,
        request_id: str,
        drive_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        request_id = validate_id(request_id, "request_id")
        drive_id = validate_id(drive_id, "drive_id")
        body = canonical_json(result)
        digest = digest_json(result)
        with self.database.write() as connection:
            existing = connection.execute(
                "SELECT * FROM quality_drives WHERE run_id = ? AND request_id = ?",
                (run_id, request_id),
            ).fetchone()
            if existing is not None:
                select_run(connection, run_id)
                return self._drive_row(existing)
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            append_event(
                connection,
                run_id,
                event="QUALITY_DRIVEN",
                actor="quality",
                payload={"request_id": request_id, "drive_id": drive_id, "result_digest": digest},
            )
            event_seq = int(
                connection.execute(
                    "SELECT event_count FROM runs WHERE id = ?", (run_id,)
                ).fetchone()[0]
            )
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO quality_drives(
                    run_id, request_id, drive_id, result_json,
                    result_digest, event_seq, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, request_id, drive_id, body, digest, event_seq, created_at),
            )
            return {
                "request_id": request_id,
                "drive_id": drive_id,
                "result": result,
                "event_seq": event_seq,
            }

    def get_drive(self, run_id: str, request_id: str) -> dict[str, Any] | None:
        request_id = validate_id(request_id, "request_id")
        with self.database.connect(readonly=True) as connection:
            select_run(connection, run_id)
            row = connection.execute(
                "SELECT * FROM quality_drives WHERE run_id = ? AND request_id = ?",
                (run_id, request_id),
            ).fetchone()
        return self._drive_row(row) if row is not None else None

    def _drive_row(self, row: Any) -> dict[str, Any]:
        result = json.loads(str(row["result_json"]))
        if not isinstance(result, dict) or digest_json(result) != str(row["result_digest"]):
            raise GuardError("PERSISTED_STATE_BROKEN", "Quality drive receipt is invalid.")
        return {
            "request_id": str(row["request_id"]),
            "drive_id": str(row["drive_id"]),
            "result": result,
            "event_seq": int(row["event_seq"]),
        }

    def confirm(
        self,
        run_id: str,
        *,
        expected_revision: int,
        request_id: str,
        confirmation_id: str,
        drive_id: str,
    ) -> dict[str, Any]:
        request_id = validate_id(request_id, "request_id")
        confirmation_id = validate_id(confirmation_id, "confirmation_id")
        drive_id = validate_id(drive_id, "drive_id")
        with self.database.write() as connection:
            existing = connection.execute(
                "SELECT * FROM quality_confirmations WHERE run_id = ? AND request_id = ?",
                (run_id, request_id),
            ).fetchone()
            if existing is not None:
                select_run(connection, run_id)
                return self._confirmation_row(existing)
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            drive = connection.execute(
                "SELECT * FROM quality_drives WHERE run_id = ? AND drive_id = ?",
                (run_id, drive_id),
            ).fetchone()
            if drive is None:
                raise GuardError("QUALITY_DRIVE_NOT_FOUND", "Quality drive does not exist.")
            outcome = self._fitness_outcome(self._drive_row(drive)["result"])
            append_event(
                connection,
                run_id,
                event="QUALITY_FITNESS_CONFIRMED",
                actor="quality",
                payload={
                    "request_id": request_id,
                    "confirmation_id": confirmation_id,
                    "drive_id": drive_id,
                    "outcome": outcome,
                },
            )
            event_seq = int(
                connection.execute(
                    "SELECT event_count FROM runs WHERE id = ?", (run_id,)
                ).fetchone()[0]
            )
            connection.execute(
                """
                INSERT INTO quality_confirmations(
                    run_id, request_id, confirmation_id, drive_id,
                    outcome, event_seq, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, request_id, confirmation_id, drive_id, outcome, event_seq, utc_now()),
            )
            return {
                "request_id": request_id,
                "confirmation_id": confirmation_id,
                "drive_id": drive_id,
                "outcome": outcome,
                "event_seq": event_seq,
            }

    def get_confirmation(self, run_id: str, request_id: str) -> dict[str, Any] | None:
        request_id = validate_id(request_id, "request_id")
        with self.database.connect(readonly=True) as connection:
            select_run(connection, run_id)
            row = connection.execute(
                "SELECT * FROM quality_confirmations WHERE run_id = ? AND request_id = ?",
                (run_id, request_id),
            ).fetchone()
        return self._confirmation_row(row) if row is not None else None

    @staticmethod
    def _confirmation_row(row: Any) -> dict[str, Any]:
        outcome = str(row["outcome"])
        if outcome not in {"FIT", "UNFIT"}:
            raise GuardError("PERSISTED_STATE_BROKEN", "Quality confirmation is invalid.")
        return {
            "request_id": str(row["request_id"]),
            "confirmation_id": str(row["confirmation_id"]),
            "drive_id": str(row["drive_id"]),
            "outcome": outcome,
            "event_seq": int(row["event_seq"]),
        }

    @staticmethod
    def _fitness_outcome(result: Any) -> str:
        if not isinstance(result, dict):
            raise GuardError("PERSISTED_STATE_BROKEN", "Quality drive result is invalid.")
        evidence = result.get("evidence")
        failed = evidence.get("failed") if isinstance(evidence, dict) else None
        if isinstance(failed, bool) or not isinstance(failed, int) or failed < 0:
            raise GuardError("PERSISTED_STATE_BROKEN", "Quality drive evidence is invalid.")
        return "FIT" if result.get("readiness") == "EXTERNAL_REVIEW" and failed == 0 else "UNFIT"
