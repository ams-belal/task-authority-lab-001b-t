"""Capture local branch/diff facts without modifying a repository."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..canonical import sha256_json


def _git(repo: Path, *args: str, strip: bool = True) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, timeout=10)
    return result.stdout.strip() if strip else result.stdout


def snapshot(repo: str | Path, base_ref: str) -> dict[str, Any]:
    """Reject changes observed during collection; this is not an atomic lock.

    The result describes the repository across the checked capture interval.
    Callers must still bind a later effect to the returned commit and base.
    """
    root = Path(repo).resolve()
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ValueError("dirty worktree: commit or remove all staged, unstaged, and untracked files before capturing authority evidence")
    branch = _git(root, "branch", "--show-current")
    commit = _git(root, "rev-parse", "HEAD")
    base_commit = _git(root, "rev-parse", base_ref)
    paths_output = _git(root, "diff", "--name-only", "-z", "--no-renames", f"{base_commit}...{commit}", strip=False)
    paths = [p for p in paths_output.split("\x00") if p]
    diff_stat = _git(root, "diff", "--stat", f"{base_commit}...{commit}")
    final_branch = _git(root, "branch", "--show-current")
    final_commit = _git(root, "rev-parse", "HEAD")
    final_base = _git(root, "rev-parse", base_ref)
    final_status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if final_status or (final_branch, final_commit, final_base) != (branch, commit, base_commit):
        raise ValueError("repository changed during collection: worktree or refs changed; retry capture")
    result = {
        "repo": str(root),
        "branch": branch,
        "commit": commit,
        "base_commit": base_commit,
        "changed_paths": sorted(paths),
        "working_tree_clean": True,
        "diff_stat": diff_stat,
    }
    result["integrity_hash"] = sha256_json(result)
    return result
