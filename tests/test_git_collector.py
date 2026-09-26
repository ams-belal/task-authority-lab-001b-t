import subprocess
import tempfile
import unittest
from pathlib import Path

from task_authority_lab.collector.git import snapshot


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


class GitCollectorTests(unittest.TestCase):
    def test_snapshot_requires_clean_worktree(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
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


if __name__ == "__main__":
    unittest.main()
