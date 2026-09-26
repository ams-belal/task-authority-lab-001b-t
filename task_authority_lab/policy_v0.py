"""Small deterministic Policy v0. Never performs an effect."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

POLICY_VERSION = "001b-t-v0"
REQUIRED_FACTS = (
    "changed_paths",
    "tests_passed",
    "checks_passed",
    "protected_paths_modified",
    "workflow_files_modified",
    "dependency_change",
    "provenance_complete",
)
TRUSTED_FACT_SOURCES = {
    "changed_paths": {"git_diff"},
    "protected_paths_modified": {"git_diff"},
    "workflow_files_modified": {"git_diff"},
    "dependency_change": {"git_diff"},
    "tests_passed": {"ci"},
    "checks_passed": {"ci"},
    "provenance_complete": {"collector"},
    "authority_control_modified": {"git_diff", "native_controls"},
}


def _instant(value: str) -> datetime:
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return instant.astimezone(timezone.utc)


def _in_scope(path: str, prefixes: list[str]) -> bool:
    normalized = str(PurePosixPath(path))
    if ".." in PurePosixPath(path).parts or path.startswith("/"):
        return False
    return any(normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def _control_path(path: str) -> bool:
    return path == ".github/CODEOWNERS" or path.startswith(".github/workflows/") or path.startswith(".github/ISSUE_TEMPLATE/") or path in {".github/dependabot.yml", "CODEOWNERS"}


def _dependency_path(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in {"pyproject.toml", "requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum"}


def _facts(evidence: list[dict[str, Any]], proposed_at: datetime) -> tuple[dict[str, Any], list[str], list[str]]:
    facts: dict[str, Any] = {}
    used: list[str] = []
    conflicts: list[str] = []
    for item in evidence:
        if item.get("available_before_effect") is not True or item.get("kind") != "deterministic":
            continue
        fact = item.get("fact")
        if not isinstance(fact, dict) or "key" not in fact or "value" not in fact:
            continue
        key = fact["key"]
        if (item.get("source") not in TRUSTED_FACT_SOURCES.get(key, set())
                or not item.get("artifact_reference") or not item.get("integrity_hash")
                or not item.get("observed_at") or _instant(item["observed_at"]) > proposed_at):
            continue
        if key in facts and facts[key] != fact["value"]:
            conflicts.append(key)
        facts[key] = fact["value"]
        used.append(item["id"])
    return facts, sorted(set(used)), sorted(set(conflicts))


def decide(request: dict[str, Any]) -> dict[str, Any]:
    """Return the same authorization *decision* for identical input.

    The caller creates a timestamped receipt separately. Policy v0 is only for
    merge candidates; other effect types do not gain accidental permission.
    """
    task = request["task"]
    delegation = request["delegation"]
    proposal = request["proposal"]
    native = request["native_controls"]
    risk = request["risk_context"]
    state = request["workflow_state"]
    effect = proposal["effect"]
    proposed_at = _instant(proposal["proposed_at"])
    facts, evidence_ids, conflicts = _facts(request["evidence"], proposed_at)
    expiry = _instant(delegation["expires_at"])
    reasons: list[str] = []

    if proposal["task_id"] != task["id"]:
        reasons.append("TASK_ID_MISMATCH")
    if proposed_at >= expiry:
        reasons.append("AUTHORITY_EXPIRED")
    if effect in delegation.get("prohibited_effects", []):
        reasons.append("EFFECT_PROHIBITED")
    if effect not in delegation.get("allowed_effects", []) + delegation.get("conditional_effects", []):
        reasons.append("EFFECT_NOT_DELEGATED")
    if risk.get("self_elevation") is True or facts.get("authority_control_modified") is True:
        reasons.append("SELF_ELEVATION")
    if risk.get("prohibited_credential_requested") is True:
        reasons.append("PROHIBITED_CREDENTIAL")
    if facts.get("changed_paths") is not None and not all(_in_scope(path, delegation.get("allowed_paths", [])) for path in facts["changed_paths"]):
        reasons.append("PATH_OUTSIDE_DELEGATION")
    if facts.get("changed_paths") is not None and any(_control_path(path) for path in facts["changed_paths"]):
        reasons.append("AUTHORITY_CONTROL_PATH_CHANGED")
    if reasons:
        return _result("DENY", reasons, evidence_ids, delegation, proposal)

    if effect != "merge_candidate":
        return _result("HUMAN", ["EFFECT_NOT_AUTOMATED_BY_POLICY_V0"], evidence_ids, delegation, proposal)

    if conflicts:
        reasons.append("CONFLICTING_EVIDENCE")
    missing = [key for key in REQUIRED_FACTS if key not in facts]
    if missing:
        reasons.append("MISSING_REQUIRED_EVIDENCE")
    if state.get("branch") != task.get("branch") or proposal.get("branch") != task.get("branch"):
        reasons.append("BRANCH_MISMATCH")
    if state.get("commit") != proposal.get("commit") or not state.get("commit"):
        reasons.append("COMMIT_MISMATCH")
    if native.get("known") is not True or not native.get("snapshot_at"):
        reasons.append("NATIVE_CONTROLS_UNKNOWN")
    elif _instant(native["snapshot_at"]) > proposed_at:
        reasons.append("NATIVE_SNAPSHOT_AFTER_PROPOSAL")
    if native.get("agent_can_merge") is not False or native.get("trusted_executor") is not True:
        reasons.append("EXECUTION_BOUNDARY_UNVERIFIED")
    if native.get("source") != "github_api_via_gh" or not native.get("integrity_hash"):
        reasons.append("NATIVE_PROVENANCE_UNVERIFIED")
    if not delegation.get("version_hash") or not delegation.get("approved_by") or delegation.get("approved_by") == proposal.get("proposed_by"):
        reasons.append("DELEGATION_PROVENANCE_UNVERIFIED")
    if risk.get("downstream_amplification") is not False or risk.get("ambient_privileged_credentials") is not False:
        reasons.append("DOWNSTREAM_AUTHORITY_UNVERIFIED")
    if facts.get("protected_paths_modified") is not False or facts.get("workflow_files_modified") is not False:
        reasons.append("PROTECTED_CHANGE")
    if facts.get("dependency_change") is not False:
        reasons.append("DEPENDENCY_CHANGE")
    if facts.get("changed_paths") is not None and any(_dependency_path(path) for path in facts["changed_paths"]):
        reasons.append("DEPENDENCY_PATH_CHANGED")
    if facts.get("tests_passed") is not True or facts.get("checks_passed") is not True:
        reasons.append("REQUIRED_CHECKS_NOT_PASSING")
    if facts.get("provenance_complete") is not True:
        reasons.append("PROVENANCE_INCOMPLETE")
    if facts.get("changed_paths") == []:
        reasons.append("EMPTY_CHANGESET")
    if reasons:
        return _result("HUMAN", sorted(set(reasons)), evidence_ids, delegation, proposal)
    return _result("AUTO_AUTHORIZE", ["MECHANICAL_MERGE_CONDITIONS_MET"], evidence_ids, delegation, proposal)


def _result(value: str, reasons: list[str], evidence_ids: list[str], delegation: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_version": POLICY_VERSION,
        "decision": value,
        "reason_codes": sorted(set(reasons)),
        "evidence_ids": evidence_ids,
        "authority_scope": {
            "resource": proposal["resource"],
            "effect": proposal["effect"],
            "branch": proposal.get("branch"),
            "commit": proposal.get("commit"),
        } if value == "AUTO_AUTHORIZE" else None,
        "required_evidence": list(REQUIRED_FACTS),
        "expiry": delegation["expires_at"],
    }
