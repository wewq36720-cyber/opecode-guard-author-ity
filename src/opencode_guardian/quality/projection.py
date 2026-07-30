from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..errors import GuardError

_READINESS = {
    "PLANNING": "NEEDS_PACKET",
    "IMPLEMENTING": "IMPLEMENTING",
    "VERIFYING": "VERIFYING",
    "REVIEW_REQUIRED": "EXTERNAL_REVIEW",
    "ACCEPTED": "ACCEPTED",
}


def project_quality_status(context: Mapping[str, Any]) -> dict[str, Any]:
    """Produce the bounded, read-only quality projection for one Guard Run."""
    run_id = _text(context, "run_id", maximum=64)
    stage = _text(context, "stage", maximum=64)
    readiness = _READINESS.get(stage)
    if readiness is None:
        raise GuardError("QUALITY_STATUS_INVALID", "Run has an unknown quality stage.")
    revision = context.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise GuardError("QUALITY_STATUS_INVALID", "Run has an invalid revision.")
    active_phase = context.get("active_phase", "")
    if not isinstance(active_phase, str) or len(active_phase) > 64:
        raise GuardError("QUALITY_STATUS_INVALID", "Run has an invalid active phase.")
    evidence = context.get("evidence", [])
    if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes, bytearray)):
        raise GuardError("QUALITY_STATUS_INVALID", "Run has invalid verification evidence.")
    failed = 0
    for item in evidence:
        if not isinstance(item, Mapping):
            raise GuardError("QUALITY_STATUS_INVALID", "Run has invalid verification evidence.")
        exit_code = item.get("exit_code")
        timed_out = item.get("timed_out")
        if (
            isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or not isinstance(timed_out, bool)
        ):
            raise GuardError("QUALITY_STATUS_INVALID", "Run has invalid verification evidence.")
        if exit_code != 0 or timed_out:
            failed += 1
    return {
        "run_id": run_id,
        "stage": stage,
        "active_phase": active_phase,
        "revision": revision,
        "evidence": {"available": len(evidence), "failed": failed},
        "readiness": readiness,
    }


def _text(context: Mapping[str, Any], field: str, *, maximum: int) -> str:
    value = context.get(field)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise GuardError("QUALITY_STATUS_INVALID", f"Run has an invalid {field}.")
    return value
