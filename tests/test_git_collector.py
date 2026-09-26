import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import task_authority_lab.collector.git as git_collector
from task_authority_lab.collector.git import snapshot


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def prepared_repo(repo: Path) -> str:
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Lab Test")
    git(repo, "config", "user.email", "lab@example.invalid")
    (repo / "source.py").write_text("value = 1\n", encoding="utf-8")
    git(repo, "add", "source.py")
    git(repo, "commit", "-m", "baseline")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "-c", "task/1")
    (repo / "source.py").write_text("value = 2\n", encoding="utf-8")
    git(repo, "commit", "-am", "task change")
    return base


class GitCollectorTests(unittest.TestCase):
    def test_snapshot_requires_clean_worktree(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            base = prepared_repo(repo)

            clean = snapshot(repo, base)
            self.assertEqual(clean["changed_paths"], ["source.py"])
            self.assertTrue(clean["working_tree_clean"])

            (repo / "untracked.py").write_text("danger = True\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "dirty worktree"):
                snapshot(repo, base)
            (repo / "untracked.py").unlink()

            (repo / "source.py").write_text("value = 3\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "dirty worktree"):
                snapshot(repo, base)
            git(repo, "add", "source.py")
            with self.assertRaisesRegex(ValueError, "dirty worktree"):
                snapshot(repo, base)

    def test_snapshot_rejects_worktree_mutation_during_collection(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            base = prepared_repo(repo)
            original = git_collector._git

            def mutate_after_diff(root, *args):
                value = original(root, *args)
                if args[:2] == ("diff", "--name-only"):
                    (repo / "late.py").write_text("late = True\n", encoding="utf-8")
                return value

            with patch.object(git_collector, "_git", side_effect=mutate_after_diff):
                with self.assertRaisesRegex(ValueError, "changed during collection"):
                    snapshot(repo, base)

    def test_snapshot_rejects_head_change_during_collection(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            base = prepared_repo(repo)
            original = git_collector._git

            def commit_after_diff(root, *args):
                value = original(root, *args)
                if args[:2] == ("diff", "--stat"):
                    (repo / "source.py").write_text("value = 3\n", encoding="utf-8")
                    git(repo, "commit", "-am", "concurrent change")
                return value

            with patch.object(git_collector, "_git", side_effect=commit_after_diff):
                with self.assertRaisesRegex(ValueError, "changed during collection"):
                    snapshot(repo, base)

    def test_snapshot_rejects_base_ref_change_during_collection(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            prepared_repo(repo)
            original = git_collector._git

            def move_base_after_diff(root, *args):
                value = original(root, *args)
                if args[:2] == ("diff", "--stat"):
                    git(repo, "update-ref", "refs/heads/main", git(repo, "rev-parse", "HEAD"))
                return value

            with patch.object(git_collector, "_git", side_effect=move_base_after_diff):
                with self.assertRaisesRegex(ValueError, "changed during collection"):
                    snapshot(repo, "main")


if __name__ == "__main__":
    unittest.main()
