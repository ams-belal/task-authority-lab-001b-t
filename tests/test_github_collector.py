import unittest
from unittest.mock import patch

from task_authority_lab.collector.github import snapshot


REPO = "example/lab"
ENVIRONMENTS_PATH = f"repos/{REPO}/environments?per_page=100&page=1"
BASE_RESPONSES = {
    f"repos/{REPO}/branches/main/protection": {"required_pull_request_reviews": {"required_approving_review_count": 1}},
    f"repos/{REPO}/rulesets?includes_parents=true": [],
    f"repos/{REPO}/actions/permissions/workflow": {"can_approve_pull_request_reviews": False},
    f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"push": True}},
}


def environment(name="staging", identifier=17, rules=None, branch_policy=None):
    return {
        "id": identifier,
        "name": name,
        "protection_rules": [] if rules is None else rules,
        "deployment_branch_policy": branch_policy,
    }


class GitHubCollectorTests(unittest.TestCase):
    def test_known_empty_and_present_environments_are_recorded(self):
        for environments in (
            {"total_count": 0, "environments": []},
            {"total_count": 1, "environments": [environment(
                rules=[
                    {"id": 8, "type": "wait_timer", "wait_timer": 30},
                    {"id": 9, "type": "required_reviewers", "prevent_self_review": True,
                     "reviewers": [{"type": "User", "reviewer": {"id": 3, "login": "reviewer"}}]},
                    {"id": 10, "type": "branch_policy"},
                ],
                branch_policy={"protected_branches": True, "custom_branch_policies": False},
            )]},
        ):
            with self.subTest(environments=environments), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route: {**BASE_RESPONSES, ENVIRONMENTS_PATH: environments}.get(route),
            ) as request:
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["environments"], environments)
                request.assert_any_call(ENVIRONMENTS_PATH)

    def test_inaccessible_environments_fail_closed(self):
        with patch("task_authority_lab.collector.github._api", side_effect=BASE_RESPONSES.get):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["environments"], "UNKNOWN")

    def test_partial_environment_page_fails_closed(self):
        for total, returned in ((31, 30), (101, 100)):
            response = {
                "total_count": total,
                "environments": [environment(f"env-{index}", index + 1) for index in range(returned)],
            }
            with self.subTest(total=total, returned=returned), patch(
                "task_authority_lab.collector.github._api",
                side_effect={**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get,
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["environments"], "UNKNOWN")

    def test_malformed_environment_and_controls_fail_closed(self):
        valid = environment()
        cases = (
            {"total_count": True, "environments": [valid]},
            {"id": 17, "protection_rules": [], "deployment_branch_policy": None},
            {**valid, "protection_rules": {"type": "wait_timer"}},
            {**valid, "protection_rules": [{"id": 8, "type": "required_reviewers", "reviewers": "ams-belal"}]},
            {**valid, "deployment_branch_policy": {"protected_branches": "yes", "custom_branch_policies": False}},
            {**valid, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
            {**valid, "protection_rules": [{"id": 8, "type": "unknown_control"}]},
        )
        for bad_entry in cases:
            response = bad_entry if "total_count" in bad_entry else {"total_count": 1, "environments": [bad_entry]}
            with self.subTest(entry=bad_entry), patch(
                "task_authority_lab.collector.github._api",
                side_effect={**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get,
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["environments"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
