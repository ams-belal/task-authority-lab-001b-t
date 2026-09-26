"""Read-only GitHub native-control adapter through the configured gh CLI.

This adapter never reads or prints token values. It distinguishes inaccessible
settings from known-absent settings; callers must fail closed on UNKNOWN.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any

from ..canonical import sha256_json


def _api(path: str) -> dict[str, Any] | list[Any] | None:
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def snapshot(repo: str, base_branch: str) -> dict[str, Any]:
    if not repo or "/" not in repo or not base_branch:
        raise ValueError("repo must be owner/name and base branch must be given")
    branch = _api(f"repos/{repo}/branches/{base_branch}/protection")
    rulesets = _api(f"repos/{repo}/rulesets?includes_parents=true")
    workflow_permissions = _api(f"repos/{repo}/actions/permissions/workflow")
    repo_meta = _api(f"repos/{repo}")
    output = {
        "repository": repo,
        "base_branch": base_branch,
        "snapshot_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "github_api_via_gh",
        "branch_protection": branch if branch is not None else "UNKNOWN",
        "rulesets": rulesets if rulesets is not None else "UNKNOWN",
        "workflow_permissions": workflow_permissions if workflow_permissions is not None else "UNKNOWN",
        "repository_metadata": {
            "default_branch": repo_meta.get("default_branch"),
            "private": repo_meta.get("private"),
            "permissions": repo_meta.get("permissions"),
        } if isinstance(repo_meta, dict) else "UNKNOWN",
    }
    output["known"] = all(output[key] != "UNKNOWN" for key in ("branch_protection", "rulesets", "workflow_permissions", "repository_metadata"))
    output["integrity_hash"] = sha256_json(output)
    return output
