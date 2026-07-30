from __future__ import annotations

import json
import os
import sys
import traceback
from collections import OrderedDict
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from .errors import GuardError
from .facade import Guardian
from .integrity import canonical_json, digest_bytes
from .persistence import StateStore
from .workspace import WorkspaceManager

MAX_MESSAGE_BYTES = 1024 * 1024
MAX_CACHE_ENTRIES = 512
ALLOWED_OPERATIONS = {
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
}


def serve(
    guardian: Guardian,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    error_stream: TextIO,
) -> int:
    cache: OrderedDict[str, tuple[str, bytes]] = OrderedDict()
    while True:
        line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
            _write(
                output_stream,
                {
                    "id": None,
                    "ok": False,
                    "error": _error("MESSAGE_TOO_LARGE", "RPC message is too large."),
                },
            )
            return 2
        request_digest = digest_bytes(line)
        request_id: str | int | None = None
        cacheable = True
        response_value: dict[str, Any]
        try:
            request = _strict_json(line)
            request_id, cache_key = _request_id(request)
            existing = cache.get(cache_key)
            if existing:
                previous_digest, response = existing
                if previous_digest != request_digest:
                    raise GuardError(
                        "REQUEST_ID_REUSED",
                        "A request ID cannot be reused with different content.",
                    )
                output_stream.write(response)
                output_stream.flush()
                continue
            result = _dispatch(guardian, request)
            response_value = {"id": request_id, "ok": True, "result": result}
        except GuardError as exc:
            cacheable = exc.code != "REQUEST_ID_REUSED"
            response_value = {"id": request_id, "ok": False, "error": exc.as_dict()}
        except Exception:
            traceback.print_exc(file=error_stream)
            response_value = {
                "id": request_id,
                "ok": False,
                "error": _error(
                    "INTERNAL_ERROR",
                    "Authority failed to process the request.",
                ),
            }
        response = _encode_response(request_id, response_value)
        if request_id is not None and cacheable:
            cache_key = f"{type(request_id).__name__}:{request_id}"
            cache[cache_key] = (request_digest, response)
            cache.move_to_end(cache_key)
            while len(cache) > MAX_CACHE_ENTRIES:
                cache.popitem(last=False)
        output_stream.write(response)
        output_stream.flush()


def _dispatch(guardian: Any, request: dict[str, Any]) -> dict[str, Any]:
    if set(request) - {"id", "op", "params"}:
        raise GuardError("INVALID_REQUEST", "RPC request contains unknown fields.")
    operation = request.get("op")
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise GuardError("UNKNOWN_OPERATION", f"RPC operation is not allowed: {operation}")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise GuardError("INVALID_REQUEST", "RPC params must be an object.")
    run_id = _text(params, "run_id", maximum=64)
    if operation == "status":
        return dict(guardian.status(run_id))
    if operation == "quality_status":
        return dict(guardian.quality_status(run_id))
    session_id = _text(params, "session_id", maximum=200)
    revision = _integer(
        params,
        "expected_revision",
        minimum=0,
        maximum=2_147_483_647,
    )
    context_digest = _text(params, "context_digest", maximum=128)
    skill_binding_digest = _text(params, "skill_binding_digest", maximum=128)
    if operation not in {"bind_task", "attach_session"}:
        guardian.assert_session(run_id, session_id)
    if operation == "authorize_tool":
        paths = _paths(params.get("paths", []))
        return dict(
            guardian.authorize_tool(
                run_id,
                _text(params, "tool_name", maximum=128),
                paths,
                call_id=_text(params, "call_id", maximum=200),
                session_id=session_id,
                expected_revision=revision,
                context_digest=context_digest,
                skill_binding_digest=skill_binding_digest,
            )
        )
    if operation == "bind_task":
        run = guardian.bind_task(
            run_id,
            expected_revision=revision,
            task=_text(params, "task", maximum=20_000),
            session_id=session_id,
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )
        return dict(guardian.status(run.run_id))
    if operation == "attach_session":
        run = guardian.attach_session(
            run_id,
            session_id,
            expected_revision=revision,
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )
        return dict(guardian.status(run.run_id))
    if operation in {"submit_baseline", "submit_spec", "submit_plan"}:
        body = params.get("body")
        if not isinstance(body, dict):
            raise GuardError("INVALID_REQUEST", "Planning artifact must be an object.")
        submit = getattr(guardian, operation)
        result = submit(
            run_id,
            expected_revision=revision,
            body=body,
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )
        return dict(result)
    if operation == "complete_phase":
        run = guardian.complete_phase(
            run_id,
            expected_revision=revision,
            phase_id=_text(params, "phase_id", maximum=64),
            outcome=_text(params, "outcome", maximum=32),
            rationale=_text(params, "rationale", maximum=2_000),
            context_digest=context_digest,
            skill_binding_digest=skill_binding_digest,
        )
        return dict(guardian.status(run.run_id))
    if operation == "drive_quality":
        return dict(
            guardian.drive_quality(
                run_id,
                expected_revision=revision,
                request_id=_text(params, "request_id", maximum=64),
                session_id=session_id,
                context_digest=context_digest,
                skill_binding_digest=skill_binding_digest,
            )
        )
    if operation == "confirm_fitness":
        return dict(
            guardian.confirm_fitness(
                run_id,
                expected_revision=revision,
                request_id=_text(params, "request_id", maximum=64),
                drive_id=_text(params, "drive_id", maximum=64),
                session_id=session_id,
                context_digest=context_digest,
                skill_binding_digest=skill_binding_digest,
            )
        )
    result = guardian.post_tool(
        run_id,
        expected_revision=revision,
        tool_name=_text(params, "tool_name", maximum=128),
        call_id=_text(params, "call_id", maximum=200),
        session_id=session_id,
        context_digest=context_digest,
        skill_binding_digest=skill_binding_digest,
    )
    return dict(guardian.status(result.run_id))


def _legacy_submit_packet_projection(
    guardian: Any,
    run_id: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Preserve the retired RPC-to-facade binding as a non-dispatchable projection.

    ``submit_packet`` is deliberately absent from ``ALLOWED_OPERATIONS``. The
    fixed V24 route directory nevertheless requires the former facade call to
    remain source-resolvable so its forbidden status cannot be silently erased.
    No RPC request can reach this private compatibility projection.
    """
    return dict(
        guardian.submit_packet(
            run_id,
            expected_revision=_integer(
                params,
                "expected_revision",
                minimum=0,
                maximum=2_147_483_647,
            ),
            body=params.get("body"),
            context_digest=_text(params, "context_digest", maximum=128),
            skill_binding_digest=_text(params, "skill_binding_digest", maximum=128),
        )
    )


def _strict_json(line: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise GuardError("DUPLICATE_JSON_KEY", f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise GuardError(
            "INVALID_JSON_NUMBER",
            f"Non-finite JSON number is forbidden: {value}",
        )

    try:
        value = json.loads(line, object_pairs_hook=pairs, parse_constant=constant)
    except UnicodeDecodeError as exc:
        raise GuardError("INVALID_UTF8", "RPC requests must use UTF-8.") from exc
    except json.JSONDecodeError as exc:
        raise GuardError("INVALID_JSON", "RPC request is not valid JSON.") from exc
    if not isinstance(value, dict):
        raise GuardError("INVALID_REQUEST", "RPC request must be an object.")
    return value


def _request_id(request: dict[str, Any]) -> tuple[str | int, str]:
    value = request.get("id")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise GuardError("INVALID_REQUEST_ID", "Request id must be a string or integer.")
    if isinstance(value, str) and (not value or len(value) > 128 or "\x00" in value):
        raise GuardError("INVALID_REQUEST_ID", "String request id is invalid.")
    return value, f"{type(value).__name__}:{value}"


def _text(params: dict[str, Any], field: str, *, maximum: int) -> str:
    value = params.get(field)
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        raise GuardError("INVALID_REQUEST", f"{field} must be bounded text.")
    return value.strip()


def _integer(params: dict[str, Any], field: str, *, minimum: int, maximum: int) -> int:
    value = params.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise GuardError(
            "INVALID_REQUEST",
            f"{field} must be between {minimum} and {maximum}.",
        )
    return value


def _paths(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 256
        or not all(isinstance(item, str) for item in value)
    ):
        raise GuardError("INVALID_REQUEST", "Tool paths must be a string list.")
    return value


def _encode_response(request_id: str | int | None, value: dict[str, Any]) -> bytes:
    encoded = (canonical_json(value) + "\n").encode()
    if len(encoded) <= MAX_MESSAGE_BYTES:
        return encoded
    fallback = {
        "id": request_id,
        "ok": False,
        "error": _error(
            "RESPONSE_TOO_LARGE",
            "RPC response exceeded one MiB; inspect stored evidence.",
        ),
    }
    return (canonical_json(fallback) + "\n").encode()


def _write(stream: BinaryIO, value: dict[str, Any]) -> None:
    stream.write(_encode_response(value.get("id"), value))
    stream.flush()


def _error(code: str, message: str) -> dict[str, Any]:
    return {"code": code, "message": message, "details": {}}


def main() -> int:
    state_dir = Path(os.environ.get("OPENCODE_GUARD_STATE_DIR", "")).expanduser().resolve()
    store = StateStore(state_dir / "guard.db")
    guardian = Guardian(store, workspace=WorkspaceManager(state_dir))
    run_id = os.environ.get("OPENCODE_GUARD_RUN_ID", "").strip()
    if run_id:
        guardian.reconcile_workspace(run_id)
    return serve(guardian, sys.stdin.buffer, sys.stdout.buffer, sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
