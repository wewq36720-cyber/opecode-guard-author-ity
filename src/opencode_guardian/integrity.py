from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256
from math import isfinite
from pathlib import Path
from typing import Any, Never

from .errors import GuardError

ZERO_HASH = "0" * 64
MAX_PERSISTED_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
STAGES = {
    "PLANNING",
    "IMPLEMENTING",
    "VERIFYING",
    "REVIEW_REQUIRED",
    "ACCEPTED",
}


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _reject_nonstandard_number(value: str) -> Never:
    raise ValueError(f"Non-standard JSON number: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        _reject_nonstandard_number(value)
    return parsed


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_json(value).encode())


def digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_bounded_json(
    value: Any,
    *,
    code: str,
    label: str,
    maximum_bytes: int = MAX_PERSISTED_JSON_BYTES,
    maximum_depth: int = MAX_JSON_DEPTH,
) -> Any:
    try:
        if not isinstance(value, str) or len(value.encode("utf-8")) > maximum_bytes:
            raise ValueError
        parsed = json.loads(
            value,
            parse_constant=_reject_nonstandard_number,
            parse_float=_parse_finite_float,
        )
        stack = [(parsed, 0)]
        while stack:
            item, depth = stack.pop()
            if isinstance(item, dict):
                if depth >= maximum_depth:
                    raise ValueError
                stack.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                if depth >= maximum_depth:
                    raise ValueError
                stack.extend((child, depth + 1) for child in item)
        return parsed
    except (json.JSONDecodeError, MemoryError, RecursionError, UnicodeError, ValueError) as exc:
        raise GuardError(code, f"{label} is malformed or exceeds integrity limits.") from exc


def verify_event_records(
    run: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    run_id = str(run["id"])
    if len(events) != int(run["event_count"]) or not events:
        raise GuardError(
            "EVENT_CHAIN_BROKEN",
            "Event count does not match the Run integrity anchor.",
            run_id=run_id,
        )
    previous = ZERO_HASH
    revision = 0
    stage = "PLANNING"
    for index, row in enumerate(events):
        envelope = {
            "run_id": row["run_id"],
            "type": row["type"],
            "actor": row["actor"],
            "payload": load_bounded_json(
                row["payload_json"],
                code="EVENT_CHAIN_BROKEN",
                label="Event payload",
            ),
            "revision": int(row["revision"]),
            "before_stage": row["before_stage"],
            "after_stage": row["after_stage"],
            "created_at": row["created_at"],
        }
        expected = digest_json({"previous_hash": previous, "event": envelope})
        if (
            int(row["seq"]) != index + 1
            or row["run_id"] != run_id
            or row["previous_hash"] != previous
            or row["event_hash"] != expected
        ):
            raise GuardError(
                "EVENT_CHAIN_BROKEN",
                "Event hash chain verification failed.",
                run_id=run_id,
                seq=row["seq"],
            )
        if index == 0:
            if (
                row["type"] != "RUN_CREATED"
                or int(row["revision"]) != 0
                or row["before_stage"] != "PLANNING"
                or row["after_stage"] != "PLANNING"
            ):
                raise GuardError(
                    "EVENT_CHAIN_BROKEN",
                    "Run has an invalid first event.",
                    run_id=run_id,
                )
        else:
            revision += 1
            if int(row["revision"]) != revision or row["before_stage"] != stage:
                raise GuardError(
                    "EVENT_CHAIN_BROKEN",
                    "Event revision or stage continuity is invalid.",
                    run_id=run_id,
                    seq=row["seq"],
                )
            after_stage = str(row["after_stage"])
            if after_stage not in STAGES:
                raise GuardError(
                    "EVENT_CHAIN_BROKEN",
                    "Event contains an unknown lifecycle stage.",
                    run_id=run_id,
                    seq=row["seq"],
                )
            stage = after_stage
        previous = expected
    if previous != run["event_head"] or revision != int(run["revision"]) or stage != run["stage"]:
        raise GuardError(
            "EVENT_CHAIN_BROKEN",
            "Event tail does not match the current Run.",
            run_id=run_id,
        )
    return {"events": len(events), "head": previous}
