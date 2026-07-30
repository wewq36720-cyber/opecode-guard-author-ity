from __future__ import annotations

import os
from pathlib import Path


def default_state_dir() -> Path:
    configured = os.environ.get("OPENCODE_GUARD_STATE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    local = os.environ.get("LOCALAPPDATA", "").strip()
    base = Path(local) if local else Path.home() / ".local" / "state"
    return (base / "opencode-guard-authority").resolve()
