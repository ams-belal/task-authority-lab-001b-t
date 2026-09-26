"""Freeze a shadow decision before the real human gate resolves."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import freeze_json, sha256_file, sha256_json
from .policy_v0 import decide


def run_shadow(request: dict[str, Any], decisions_root: str | Path) -> dict[str, Any]:
    gate = request.get("gate", {})
    if gate.get("status") != "pending":
        raise ValueError("the real human gate must still be pending")
    if gate.get("decision") is not None or gate.get("decided_at") is not None:
        raise ValueError("human outcome is already present")
    proposal = request["proposal"]
    if gate.get("effect_id") != proposal["id"]:
        raise ValueError("gate and proposal do not match")

    decision = decide(request)
    input_hash = sha256_json(request)
    policy_path = Path(__file__).with_name("policy_v0.py")
    policy_hash = sha256_file(policy_path)
    decision_hash = sha256_json(decision)
    decision_id = re.sub(r"[^A-Za-z0-9_-]", "-", proposal["id"]) + "-" + input_hash[:12]
    destination = Path(decisions_root) / decision_id
    destination.mkdir(parents=True, exist_ok=False)

    missing_m0 = []
    if not gate.get("required_by") or not gate.get("rule_reference") or not gate.get("requested_at"):
        missing_m0.append("REQUIRED_HUMAN_GATE_UNVERIFIED")
    if request.get("native_controls", {}).get("known") is not True:
        missing_m0.append("NATIVE_CONTROLS_UNKNOWN")
    if not request.get("delegation", {}).get("version_hash") or not request.get("delegation", {}).get("approved_by"):
        missing_m0.append("DELEGATION_NOT_FROZEN")
    if not request.get("agent_events"):
        missing_m0.append("AGENT_WORK_NOT_RECORDED")

    try:
        freeze_json(destination / "input.json", request)
        freeze_json(destination / "decision.json", decision)
        receipt = {
            "decision_id": decision_id,
            "task_id": request["task"]["id"],
            "effect_id": proposal["id"],
            "policy_version": decision["policy_version"],
            "policy_sha256": policy_hash,
            "decision": decision["decision"],
            "reason_codes": decision["reason_codes"],
            "evidence_ids": decision["evidence_ids"],
            "input_sha256": input_hash,
            "decision_sha256": decision_hash,
            "authority_scope": decision["authority_scope"],
            "expiry": decision["expiry"],
            "decided_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "human_gate_pending_at_decision": True,
            "m0_validity": "VALID_CANDIDATE" if not missing_m0 else "INCOMPLETE",
            "m0_missing": missing_m0,
            "shadow_only": True,
        }
        freeze_json(destination / "receipt.json", receipt)
    except BaseException:
        # Preserve partial data for audit; never retry under the same ID silently.
        raise
    return {"directory": str(destination), "receipt": receipt}


def verify_receipt(directory: str | Path) -> dict[str, Any]:
    root = Path(directory)
    request = json.loads((root / "input.json").read_text(encoding="utf-8"))
    decision = json.loads((root / "decision.json").read_text(encoding="utf-8"))
    receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
    checks = {
        "input_hash": sha256_json(request) == receipt["input_sha256"],
        "decision_hash": sha256_json(decision) == receipt["decision_sha256"],
        "policy_hash": sha256_file(Path(__file__).with_name("policy_v0.py")) == receipt["policy_sha256"],
        "decision_replay": decide(request) == decision,
        "gate_pending": request["gate"]["status"] == "pending" and request["gate"].get("decision") is None,
    }
    return {"valid": all(checks.values()), "checks": checks, "receipt": receipt}
