"""Capture local branch/diff facts without modifying a repository."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..canonical import sha256_json


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def snapshot(repo: str | Path, base_ref: str) -> dict[str, Any]:
    root = Path(repo).resolve()
    branch = _git(root, "branch", "--show-current")
    commit = _git(root, "rev-parse", "HEAD")
    base_commit = _git(root, "rev-parse", base_ref)
    paths = _git(root, "diff", "--name-only", "--no-renames", f"{base_commit}...{commit}").splitlines()
    status = _git(root, "status", "--porcelain")
    result = {
        "repo": str(root),
        "branch": branch,
        "commit": commit,
        "base_commit": base_commit,
        "changed_paths": sorted(paths),
        "working_tree_clean": not bool(status),
        "diff_stat": _git(root, "diff", "--stat", f"{base_commit}...{commit}"),
    }
    result["integrity_hash"] = sha256_json(result)
    return result
