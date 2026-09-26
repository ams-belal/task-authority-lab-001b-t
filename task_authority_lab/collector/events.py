"""Append-only local event envelopes for relevant agent and gate events."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..canonical import freeze_json


def record_event(event: dict[str, Any], directory: str | Path) -> dict[str, Any]:
    required = ("id", "task_id", "actor", "action", "target", "result", "source", "artifact_reference")
    missing = [key for key in required if not event.get(key)]
    if missing:
        raise ValueError("missing event fields: " + ", ".join(missing))
    value = dict(event)
    value["recorded_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "-", value["id"])
    path = Path(directory) / (safe_id + ".json")
    digest = freeze_json(path, value)
    return {"path": str(path), "sha256": digest}
