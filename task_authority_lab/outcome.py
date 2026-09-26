"""Record a human outcome after, and separate from, a frozen shadow receipt."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import freeze_json
from .shadow import verify_receipt


def _instant(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp needs timezone")
    return result.astimezone(timezone.utc)


def record_human_outcome(decision_directory: str | Path, outcome: dict[str, Any]) -> dict[str, Any]:
    verification = verify_receipt(decision_directory)
    if not verification["valid"]:
        raise ValueError("shadow receipt failed verification")
    receipt = verification["receipt"]
    if outcome.get("effect_id") != receipt["effect_id"]:
        raise ValueError("outcome effect does not match receipt")
    if outcome.get("decision") not in {"APPROVE", "MODIFY", "REJECT", "ESCALATE"}:
        raise ValueError("invalid human gate result")
    if not outcome.get("actor") or not outcome.get("evidence_reference"):
        raise ValueError("human actor and gate evidence are required")
    if _instant(outcome["decided_at"]) <= _instant(receipt["decided_at"]):
        raise ValueError("human outcome must be later than shadow decision")
    request = json.loads((Path(decision_directory) / "input.json").read_text(encoding="utf-8"))
    requested_at = _instant(request["gate"]["requested_at"])
    decided_at = _instant(outcome["decided_at"])
    value = dict(outcome)
    value["decision_id"] = receipt["decision_id"]
    value["delay_seconds"] = int((decided_at - requested_at).total_seconds())
    path = Path(decision_directory) / "human_outcome.json"
    digest = freeze_json(path, value)
    return {"path": str(path), "sha256": digest, "delay_seconds": value["delay_seconds"]}
