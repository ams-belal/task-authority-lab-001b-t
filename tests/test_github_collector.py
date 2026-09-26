import unittest
from unittest.mock import patch

from task_authority_lab.collector.github import snapshot


REPO = "example/lab"
BASE_RESPONSES = {
    f"repos/{REPO}/branches/main/protection": {"required_pull_request_reviews": {"required_approving_review_count": 1}},
    f"repos/{REPO}/rulesets?includes_parents=true": [],
    f"repos/{REPO}/actions/permissions/workflow": {"can_approve_pull_request_reviews": False},
    f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"push": True}},
}


class GitHubCollectorTests(unittest.TestCase):
    def test_known_empty_and_present_environments_are_recorded(self):
        path = f"repos/{REPO}/environments"
        for environments in (
            {"total_count": 0, "environments": []},
            {"total_count": 1, "environments": [{"name": "staging", "id": 17}]},
        ):
            with self.subTest(environments=environments), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route: {**BASE_RESPONSES, path: environments}.get(route),
            ) as request:
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["environments"], environments)
                request.assert_any_call(path)

    def test_inaccessible_environments_fail_closed(self):
        with patch("task_authority_lab.collector.github._api", side_effect=BASE_RESPONSES.get):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["environments"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
