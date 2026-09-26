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
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ValueError("dirty worktree: commit or remove all staged, unstaged, and untracked files before capturing authority evidence")
    branch = _git(root, "branch", "--show-current")
    commit = _git(root, "rev-parse", "HEAD")
    base_commit = _git(root, "rev-parse", base_ref)
    paths = _git(root, "diff", "--name-only", "--no-renames", f"{base_commit}...{commit}").splitlines()
    result = {
        "repo": str(root),
        "branch": branch,
        "commit": commit,
        "base_commit": base_commit,
        "changed_paths": sorted(paths),
        "working_tree_clean": True,
        "diff_stat": _git(root, "diff", "--stat", f"{base_commit}...{commit}"),
    }
    result["integrity_hash"] = sha256_json(result)
    return result
