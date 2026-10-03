import subprocess
import unittest
from unittest.mock import patch

from task_authority_lab.collector.github import _api, snapshot


REPO = "example/lab"
ENVIRONMENTS_PATH = f"repos/{REPO}/environments?per_page=100&page=1"
RULESETS_PATH = f"repos/{REPO}/rulesets?includes_parents=true&per_page=100"
RULESET_41_PATH = f"repos/{REPO}/rulesets/41?includes_parents=true"
RULESET_42_PATH = f"repos/{REPO}/rulesets/42?includes_parents=true"

VALID_RULESET_41 = {
    "id": 41,
    "name": "one",
    "target": "branch",
    "source_type": "Repository",
    "source": REPO,
    "enforcement": "active",
    "bypass_actors": [{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}],
    "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
    "rules": [{"type": "pull_request", "parameters": {
        "required_approving_review_count": 1,
        "require_last_push_approval": False,
        "dismiss_stale_reviews_on_push": True,
        "require_code_owner_review": True,
        "required_review_thread_resolution": True,
    }}]
}
VALID_RULESET_42 = {
    "id": 42,
    "name": "two",
    "target": "branch",
    "source_type": "Repository",
    "source": REPO,
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
    "rules": [{"type": "required_linear_history"}]
}

VALID_BRANCH_PROTECTION = {
    "required_pull_request_reviews": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews": False,
        "require_code_owner_reviews": False,
        "require_last_push_approval": False,
    },
    "required_status_checks": {
        "strict": True,
        "checks": [{"context": "ci"}],
    },
    "enforce_admins": {
        "enabled": True,
    },
}

BASE_RESPONSES = {
    f"repos/{REPO}/branches/main/protection": VALID_BRANCH_PROTECTION,
    RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}]],
    RULESET_41_PATH: VALID_RULESET_41,
    RULESET_42_PATH: VALID_RULESET_42,
    f"repos/{REPO}/actions/permissions/workflow": {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
    f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
}


def environment(name="staging", identifier=17, rules=None, branch_policy=None):
    return {
        "id": identifier,
        "name": name,
        "protection_rules": [] if rules is None else rules,
        "deployment_branch_policy": branch_policy,
    }


class GitHubCollectorTests(unittest.TestCase):
    def test_rulesets_request_uses_all_pages(self):
        with patch("task_authority_lab.collector.github.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, "[[],[]]", "")) as run:
            self.assertEqual(_api(RULESETS_PATH, paginate=True), [[], []])
        run.assert_called_once_with(
            ["gh", "api", "--paginate", "--slurp", RULESETS_PATH],
            capture_output=True, text=True, timeout=10,
        )

    def test_paginated_rulesets_are_combined(self):
        first = {"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}
        second = {"id": 42, "name": "two", "source_type": "Repository", "source": REPO, "enforcement": "active"}
        detail_41 = {**VALID_RULESET_41, **first}
        detail_42 = {**VALID_RULESET_42, **second}
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESETS_PATH: [[first], [second]],
            f"repos/{REPO}/rulesets/41?includes_parents=true": detail_41,
            f"repos/{REPO}/rulesets/42?includes_parents=true": detail_42,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)) as request:
            result = snapshot(REPO, "main")
        request.assert_any_call(RULESETS_PATH, paginate=True)
        self.assertTrue(result["known"])
        self.assertEqual(result["rulesets"], [detail_41, detail_42])

    def test_malformed_ruleset_pages_fail_closed(self):
        valid = {"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}
        for pages in (
            [valid],  # A raw first page is not proof that later pages were fetched.
            [[valid], {"message": "later page failed"}],
            [[valid], [{**valid}]],
            [[{**valid, "id": True}]],
            [[{**valid, "name": ""}]],
            [[{**valid, "enforcement": "unexpected"}]],
            [[{**valid, "enforcement": []}]],
            [[{**valid, "enforcement": {}}]],
            [[{**valid, "enforcement": None}]],
            [[{**valid, "enforcement": 123}]],
        ):
            responses = {**BASE_RESPONSES, ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                         RULESETS_PATH: pages}
            with self.subTest(pages=pages), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_ruleset_detail_read_failure_fails_closed(self):
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESET_41_PATH: None,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_malformed_ruleset_detail_fails_closed(self):
        for bad_detail in (
            {"id": 41},
            {**VALID_RULESET_41, "rules": "not-a-list"},
            {**VALID_RULESET_41, "enforcement": "unexpected"},
            {**VALID_RULESET_41, "enforcement": []},
            {**VALID_RULESET_41, "enforcement": {}},
            {**VALID_RULESET_41, "enforcement": None},
            {**VALID_RULESET_41, "enforcement": 123},
            {**VALID_RULESET_41, "conditions": "not-a-dict"},
        ):
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: bad_detail,
            }
            with self.subTest(bad_detail=bad_detail), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_valid_ruleset_enforcement_values_succeed(self):
        for enforcement in ("active", "evaluate", "disabled"):
            valid_summary = {"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": enforcement}
            valid_detail = {**VALID_RULESET_41, "enforcement": enforcement}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[valid_summary]],
                RULESET_41_PATH: valid_detail,
            }
            with self.subTest(enforcement=enforcement), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["rulesets"], [valid_detail])

    def test_mismatched_ruleset_identity_fails_closed(self):
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESET_41_PATH: {**VALID_RULESET_41, "id": 999},
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_omitted_bypass_actors_fails_closed(self):
        detail = dict(VALID_RULESET_41)
        del detail["bypass_actors"]
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESET_41_PATH: detail,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_malformed_bypass_actors_shape_fails_closed(self):
        for bad_bypass in (
            "not-a-list",
            [{"actor_type": ""}],
            [{"actor_type": "UnrecognizedActor", "bypass_mode": "always", "actor_id": 1}],
            [{"actor_type": "Integration", "bypass_mode": ""}],
            [{"actor_type": "Integration", "bypass_mode": "unrestricted", "actor_id": 1}],
            [{"actor_type": "DeployKey", "bypass_mode": "pull_request"}],
            [{"actor_type": "Integration", "bypass_mode": "always"}],
            [{"actor_type": "Integration", "bypass_mode": "always", "actor_id": "not-int"}],
            [{"actor_type": "Integration", "bypass_mode": "always", "actor_id": None}],
            [{"actor_type": "Integration", "bypass_mode": "always", "actor_id": True}],
            [{"actor_type": "Integration", "bypass_mode": "always", "actor_id": -1}],
            [{"actor_type": "Integration", "bypass_mode": "always", "actor_id": 0}],
            [{"actor_type": "RepositoryRole", "bypass_mode": "always", "actor_id": "1"}],
            [{"actor_type": "DeployKey", "bypass_mode": "always", "actor_id": 1}],
        ):
            detail = {**VALID_RULESET_41, "bypass_actors": bad_bypass}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: detail,
            }
            with self.subTest(bad_bypass=bad_bypass), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

        # Test pull_request mode on non-branch target with non-enterprise actors
        for bad_pr_bypass in (
            {"target": "repository", "bypass_actors": [{"actor_type": "Integration", "bypass_mode": "pull_request", "actor_id": 1}]},
        ):
            bad_pr_target = {**VALID_RULESET_41, **bad_pr_bypass}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: bad_pr_target,
            }
            with self.subTest(bad_pr_target=bad_pr_target), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_non_branch_pull_request_rule_fails_closed(self):
        for target, conditions in (
            ("repository", {
                "repository_name": {"include": ["*"], "exclude": []},
            }),
            ("tag", {
                "ref_name": {"include": ["refs/tags/*"], "exclude": []},
            }),
        ):
            detail = {
                "id": 41,
                "name": "one",
                "target": target,
                "source_type": "Repository",
                "source": REPO,
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": conditions,
                "rules": [{"type": "pull_request", "parameters": {
                    "required_approving_review_count": 1,
                    "require_last_push_approval": False,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": True,
                    "required_review_thread_resolution": True,
                }}],
            }
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}]],
                RULESET_41_PATH: detail,
            }
            with self.subTest(target=target), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_valid_non_branch_rules_succeed(self):
        for target, conditions in (
            ("repository", {
                "repository_name": {"include": ["*"], "exclude": []},
            }),
            ("tag", {
                "ref_name": {"include": ["refs/tags/*"], "exclude": []},
            }),
        ):
            detail = {
                "id": 41,
                "name": "one",
                "target": target,
                "source_type": "Repository",
                "source": REPO,
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": conditions,
                "rules": [{"type": "required_linear_history"}],
            }
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}]],
                RULESET_41_PATH: detail,
            }
            with self.subTest(target=target), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["rulesets"], [detail])

    def test_enterprise_malformed_bypass_actors_shape_fails_closed(self):
        base_ent_detail = {
            "id": 41,
            "name": "one",
            "target": "branch",
            "source_type": "Enterprise",
            "source": "example/enterprise",
            "enforcement": "active",
            "bypass_actors": [{"actor_type": "EnterpriseOwner", "bypass_mode": "always"}],
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "organization_name": {"include": ["org"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []},
            },
            "rules": [{"type": "pull_request", "parameters": {
                "required_approving_review_count": 1,
                "require_last_push_approval": False,
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": True,
                "required_review_thread_resolution": True,
            }}],
        }
        valid_responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
            RULESET_41_PATH: base_ent_detail,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: valid_responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["rulesets"], [base_ent_detail])

        for bad_ent_bypass in (
            [{"actor_type": "EnterpriseRole", "bypass_mode": "always"}],
            [{"actor_type": "EnterpriseRole", "bypass_mode": "always", "actor_id": "5"}],
            [{"actor_type": "EnterpriseRole", "bypass_mode": "always", "actor_id": None}],
            [{"actor_type": "EnterpriseRole", "bypass_mode": "always", "actor_id": True}],
            [{"actor_type": "EnterpriseRole", "bypass_mode": "always", "actor_id": 0}],
            [{"actor_type": "EnterpriseRole", "bypass_mode": "always", "actor_id": -5}],
            [{"actor_type": "EnterpriseRole", "actor_id": 5, "bypass_mode": "unsupported"}],
            [{"actor_type": "EnterpriseOwner", "bypass_mode": "always", "actor_id": "1"}],
            [{"actor_type": "EnterpriseOwner", "bypass_mode": "always", "actor_id": True}],
            [{"actor_type": "EnterpriseOwner", "bypass_mode": "invalid"}],
        ):
            detail = {**base_ent_detail, "bypass_actors": bad_ent_bypass}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
                RULESET_41_PATH: detail,
            }
            with self.subTest(bad_ent_bypass=bad_ent_bypass), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_enterprise_non_branch_pull_request_bypass_fails_closed(self):
        for target, conditions in (
            ("repository", {
                "organization_name": {"include": ["org"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []},
            }),
            ("tag", {
                "ref_name": {"include": ["refs/tags/*"], "exclude": []},
                "organization_name": {"include": ["org"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []},
            }),
        ):
            for actor_type, actor_id in (
                ("EnterpriseOwner", None),
                ("EnterpriseRole", 5),
            ):
                base_detail = {
                    "id": 41,
                    "name": "one",
                    "target": target,
                    "source_type": "Enterprise",
                    "source": "example/enterprise",
                    "enforcement": "active",
                    "bypass_actors": [{"actor_type": actor_type, **({"actor_id": actor_id} if actor_id is not None else {}), "bypass_mode": "always"}],
                    "conditions": conditions,
                    "rules": [{"type": "required_linear_history"}],
                }
                valid_responses = {
                    **BASE_RESPONSES,
                    ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                    RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
                    RULESET_41_PATH: base_detail,
                }
                with self.subTest(target=target, actor_type=actor_type, bypass_mode="always"), patch(
                    "task_authority_lab.collector.github._api",
                    side_effect=lambda route, **kwargs: valid_responses.get(route),
                ):
                    result = snapshot(REPO, "main")
                    self.assertTrue(result["known"])
                    self.assertEqual(result["rulesets"], [base_detail])

                invalid_detail = {
                    **base_detail,
                    "bypass_actors": [{"actor_type": actor_type, **({"actor_id": actor_id} if actor_id is not None else {}), "bypass_mode": "pull_request"}]
                }
                invalid_responses = {
                    **BASE_RESPONSES,
                    ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                    RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
                    RULESET_41_PATH: invalid_detail,
                }
                with self.subTest(target=target, actor_type=actor_type, bypass_mode="pull_request"), patch(
                    "task_authority_lab.collector.github._api",
                    side_effect=lambda route, **kwargs: invalid_responses.get(route),
                ):
                    result = snapshot(REPO, "main")
                    self.assertFalse(result["known"])
                    self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_valid_bypass_actor_combinations_succeed(self):
        for valid_bypass in (
            [],
            [{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"}],
            [{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "pull_request"}],
            [{"actor_id": 1, "actor_type": "Integration", "bypass_mode": "exempt"}],
            [{"actor_type": "OrganizationAdmin", "bypass_mode": "always"}],
            [{"actor_type": "OrganizationAdmin", "actor_id": 1, "bypass_mode": "always"}],
            [{"actor_id": 2, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
            [{"actor_id": 3, "actor_type": "Team", "bypass_mode": "always"}],
            [{"actor_id": 4, "actor_type": "User", "bypass_mode": "always"}],
            [{"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}],
            [{"actor_type": "DeployKey", "bypass_mode": "always"}],
        ):
            detail = {**VALID_RULESET_41, "bypass_actors": valid_bypass}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: detail,
            }
            with self.subTest(valid_bypass=valid_bypass), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["rulesets"], [detail])

    def test_inherited_enterprise_ruleset_bypass_actors_succeed(self):
        for valid_ent_bypass in (
            [{"actor_type": "EnterpriseOwner", "bypass_mode": "always"}],
            [{"actor_type": "EnterpriseOwner", "actor_id": 1, "bypass_mode": "always"}],
            [{"actor_type": "EnterpriseOwner", "actor_id": None, "bypass_mode": "always"}],
            [{"actor_id": 42, "actor_type": "EnterpriseRole", "bypass_mode": "always"}],
            [{"actor_id": 42, "actor_type": "EnterpriseRole", "bypass_mode": "pull_request"}],
        ):
            ent_detail = {
                "id": 41,
                "name": "one",
                "target": "branch",
                "source_type": "Enterprise",
                "source": "example/enterprise",
                "enforcement": "active",
                "bypass_actors": valid_ent_bypass,
                "conditions": {
                    "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                    "organization_name": {"include": ["org"], "exclude": []},
                    "repository_name": {"include": ["*"], "exclude": []},
                },
                "rules": [{"type": "pull_request", "parameters": {
                    "required_approving_review_count": 1,
                    "require_last_push_approval": False,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": True,
                    "required_review_thread_resolution": True,
                }}],
            }
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
                RULESET_41_PATH: ent_detail,
            }
            with self.subTest(valid_ent_bypass=valid_ent_bypass), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["rulesets"], [ent_detail])

    def test_enterprise_bypass_actors_fail_closed_on_repository_and_organization_sources(self):
        for source_type, source_val, conditions in (
            ("Repository", REPO, {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}),
            ("Organization", "example/org", {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []},
            }),
        ):
            for ent_bypass in (
                [{"actor_type": "EnterpriseOwner", "bypass_mode": "always"}],
                [{"actor_type": "EnterpriseOwner", "actor_id": 1, "bypass_mode": "always"}],
                [{"actor_type": "EnterpriseOwner", "actor_id": None, "bypass_mode": "always"}],
                [{"actor_id": 5, "actor_type": "EnterpriseRole", "bypass_mode": "always"}],
                [{"actor_id": 5, "actor_type": "EnterpriseRole", "bypass_mode": "pull_request"}],
            ):
                detail = {
                    "id": 41,
                    "name": "one",
                    "target": "branch",
                    "source_type": source_type,
                    "source": source_val,
                    "enforcement": "active",
                    "bypass_actors": ent_bypass,
                    "conditions": conditions,
                    "rules": [{"type": "required_linear_history"}],
                }
                responses = {
                    **BASE_RESPONSES,
                    ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                    RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": source_type, "source": source_val, "enforcement": "active"}]],
                    RULESET_41_PATH: detail,
                }
                with self.subTest(source_type=source_type, ent_bypass=ent_bypass), patch(
                    "task_authority_lab.collector.github._api",
                    side_effect=lambda route, **kwargs: responses.get(route),
                ):
                    result = snapshot(REPO, "main")
                    self.assertFalse(result["known"])
                    self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_mismatched_ruleset_detail_fields_fail_closed(self):
        for mismatch in (
            {"name": "mismatched-name"},
            {"source_type": "Organization"},
            {"source": "other/repo"},
            {"enforcement": "evaluate"},
        ):
            detail = {**VALID_RULESET_41, **mismatch}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: detail,
            }
            with self.subTest(mismatch=mismatch), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_redacted_ruleset_fields_fail_closed(self):
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESET_41_PATH: {
                **VALID_RULESET_41,
                "rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": None}}]
            },
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["rulesets"], "UNKNOWN")

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
                side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: environments}.get(route),
            ) as request:
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["environments"], environments)
                request.assert_any_call(ENVIRONMENTS_PATH)

    def test_inaccessible_environments_fail_closed(self):
        with patch("task_authority_lab.collector.github._api", side_effect=lambda route, **kwargs: BASE_RESPONSES.get(route)):
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
                side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
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
                side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["environments"], "UNKNOWN")

    def test_environment_branch_policy_rule_omitting_deployment_policy_fails_closed(self):
        env = environment(
            rules=[{"id": 10, "type": "branch_policy"}],
            branch_policy=None,
        )
        response = {"total_count": 1, "environments": [env]}
        with patch(
            "task_authority_lab.collector.github._api",
            side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
        ):
            result = snapshot(REPO, "main")
            self.assertFalse(result["known"])
            self.assertEqual(result["environments"], "UNKNOWN")

    def test_environment_branch_policy_rule_missing_deployment_policy_key_fails_closed(self):
        env = environment(
            rules=[{"id": 10, "type": "branch_policy"}],
            branch_policy={"protected_branches": True, "custom_branch_policies": False},
        )
        del env["deployment_branch_policy"]
        response = {"total_count": 1, "environments": [env]}
        with patch(
            "task_authority_lab.collector.github._api",
            side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
        ):
            result = snapshot(REPO, "main")
            self.assertFalse(result["known"])
            self.assertEqual(result["environments"], "UNKNOWN")

    def test_environment_branch_policy_rule_with_valid_deployment_policy_succeeds(self):
        env = environment(
            rules=[{"id": 10, "type": "branch_policy"}],
            branch_policy={"protected_branches": True, "custom_branch_policies": False},
        )
        response = {"total_count": 1, "environments": [env]}
        with patch(
            "task_authority_lab.collector.github._api",
            side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
        ):
            result = snapshot(REPO, "main")
            self.assertTrue(result["known"])
            self.assertEqual(result["environments"], response)

    def test_environment_without_branch_policy_rule_with_null_deployment_policy_succeeds(self):
        env = environment(
            rules=[{"id": 8, "type": "wait_timer", "wait_timer": 30}],
            branch_policy=None,
        )
        response = {"total_count": 1, "environments": [env]}
        with patch(
            "task_authority_lab.collector.github._api",
            side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
        ):
            result = snapshot(REPO, "main")
            self.assertTrue(result["known"])
            self.assertEqual(result["environments"], response)

    def test_environment_wait_timer_valid_boundaries_succeed(self):
        for timer in (0, 43200):
            env = environment(
                rules=[{"id": 8, "type": "wait_timer", "wait_timer": timer}],
                branch_policy=None,
            )
            response = {"total_count": 1, "environments": [env]}
            with self.subTest(timer=timer), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["environments"], response)

    def test_environment_wait_timer_over_limit_fails_closed(self):
        for timer in (43201, 50000, 1000000):
            env = environment(
                rules=[{"id": 8, "type": "wait_timer", "wait_timer": timer}],
                branch_policy=None,
            )
            response = {"total_count": 1, "environments": [env]}
            with self.subTest(timer=timer), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: {**BASE_RESPONSES, ENVIRONMENTS_PATH: response}.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["environments"], "UNKNOWN")

    def test_omitted_pull_request_effective_gate_fields_fail_closed(self):
        for bad_params in (
            {},
            {"required_approving_review_count": 1},
            {"required_approving_review_count": 1, "require_last_push_approval": False},
        ):
            detail = {**VALID_RULESET_41, "rules": [{"type": "pull_request", "parameters": bad_params}]}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: detail,
            }
            with self.subTest(bad_params=bad_params), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_omitted_required_status_checks_fields_fail_closed(self):
        for bad_params in (
            {},
            {"required_status_checks": [{"context": "ci"}]},
            {"strict_required_status_checks_policy": True},
        ):
            detail = {
                **VALID_RULESET_41,
                "rules": [{"type": "required_status_checks", "parameters": bad_params}]
            }
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: detail,
            }
            with self.subTest(bad_params=bad_params), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_omitted_or_malformed_targeting_conditions_fail_closed(self):
        for bad_conditions in (
            None,
            {},
            {"other_condition": {"include": ["refs/heads/main"], "exclude": []}},
            {"ref_name": {}},
            {"ref_name": {"exclude": []}},
            {"ref_name": {"include": [], "exclude": []}},
            {"ref_name": {"include": [""], "exclude": []}},
            {"ref_name": {"include": [123], "exclude": []}},
            {"ref_name": {"include": ["refs/heads/main"], "exclude": [123]}},
        ):
            detail = {**VALID_RULESET_41, "conditions": bad_conditions}
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: detail,
            }
            with self.subTest(bad_conditions=bad_conditions), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_unsupported_rule_or_condition_shapes_fail_closed(self):
        for bad_rule_or_cond in (
            {**VALID_RULESET_41, "rules": [{"type": "unsupported_rule_type"}]},
            {**VALID_RULESET_41, "conditions": {"unsupported_condition": {}}},
        ):
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESET_41_PATH: bad_rule_or_cond,
            }
            with self.subTest(bad=bad_rule_or_cond), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

    def test_representative_valid_details_succeed(self):
        valid_status_checks_detail = {
            **VALID_RULESET_41,
            "rules": [{
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": "ci/test", "integration_id": 123}],
                    "strict_required_status_checks_policy": True
                }
            }]
        }
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}]],
            RULESET_41_PATH: valid_status_checks_detail,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["rulesets"], [valid_status_checks_detail])

    def test_organization_enterprise_branch_tag_ruleset_targeting_constraints(self):
        org_base = {
            **VALID_RULESET_41,
            "source_type": "Organization",
            "source": "example/org",
        }
        missing_selector = {
            **org_base,
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
        }
        selector_alone = {
            **org_base,
            "conditions": {"repository_name": {"include": ["*"], "exclude": []}}
        }
        malformed_selectors = [
            {**org_base, "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []},
                "repository_id": {"repository_ids": [1]}
            }},
            {**org_base, "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "repository_id": {"repository_ids": [-1]}
            }},
            {**org_base, "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": [], "push": True},
                "repository_name": {"include": ["*"], "exclude": []}
            }},
        ]
        valid_combined = {
            **org_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }

        for bad_detail in (missing_selector, selector_alone, *malformed_selectors):
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Organization", "source": "example/org", "enforcement": "active"}]],
                RULESET_41_PATH: bad_detail,
                f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            }
            with self.subTest(detail=bad_detail), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

        responses_valid = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Organization", "source": "example/org", "enforcement": "active"}]],
            RULESET_41_PATH: valid_combined,
            f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses_valid.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["rulesets"], [valid_combined])

    def test_enterprise_ruleset_targeting_constraints(self):
        ent_base = {
            **VALID_RULESET_41,
            "source_type": "Enterprise",
            "source": "example/enterprise",
        }
        missing_org = {
            **ent_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }
        missing_repo = {
            **ent_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "organization_name": {"include": ["org"], "exclude": []}
            }
        }
        missing_ref_name_branch = {
            **ent_base,
            "conditions": {
                "organization_name": {"include": ["org"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }
        unsupported_repo_id = {
            **ent_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "organization_name": {"include": ["org"], "exclude": []},
                "repository_id": {"repository_ids": [1]}
            }
        }
        multiple_org = {
            **ent_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "organization_name": {"include": ["org1"], "exclude": []},
                "organization_id": {"organization_ids": [1]},
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }
        malformed_org = {
            **ent_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "organization_id": {"organization_ids": [-1]},
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }
        valid_branch = {
            **ent_base,
            "conditions": {
                "ref_name": {"include": ["refs/heads/main"], "exclude": []},
                "organization_name": {"include": ["org"], "exclude": []},
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }
        valid_repo_target = {
            **ent_base,
            "target": "repository",
            "rules": [{"type": "required_linear_history"}],
            "conditions": {
                "organization_id": {"organization_ids": [10]},
                "repository_property": {
                    "include": [
                        {"name": "prop", "source": "custom", "property_values": ["val"]}
                    ]
                }
            }
        }
        valid_org_property_target = {
            **ent_base,
            "target": "repository",
            "rules": [{"type": "required_linear_history"}],
            "conditions": {
                "organization_property": {
                    "include": [
                        {"name": "org_prop", "property_values": ["org_val"]}
                    ]
                },
                "repository_name": {"include": ["*"], "exclude": []}
            }
        }
        malformed_property_selectors = [
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "repository_property": {"property_name": "prop", "source": "custom", "values": ["val"]}
                }
            },
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "repository_property": {"include": [{"property_values": ["val"]}]}
                }
            },
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "repository_property": {"include": [{"name": "prop"}]}
                }
            },
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "repository_property": {"include": [{"name": "prop", "property_values": "not-list"}]}
                }
            },
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "repository_property": {"include": [{"name": "prop", "source": "invalid", "property_values": ["val"]}]}
                }
            },
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "organization_property": {"include": [{"name": "prop", "source": "custom", "property_values": ["val"]}]}
                }
            },
            {
                **ent_base,
                "target": "repository",
                "conditions": {
                    "organization_id": {"organization_ids": [10]},
                    "repository_property": {"include": []}
                }
            },
        ]

        for bad_detail in (missing_org, missing_repo, missing_ref_name_branch, unsupported_repo_id, multiple_org, malformed_org, *malformed_property_selectors):
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
                RULESET_41_PATH: bad_detail,
                f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            }
            with self.subTest(detail=bad_detail), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["rulesets"], "UNKNOWN")

        for good_detail in (valid_branch, valid_repo_target, valid_org_property_target):
            responses_valid = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Enterprise", "source": "example/enterprise", "enforcement": "active"}]],
                RULESET_41_PATH: good_detail,
                f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            }
            with self.subTest(detail=good_detail), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses_valid.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["rulesets"], [good_detail])

    def test_valid_repository_metadata_succeeds(self):
        for valid_meta in (
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False, "maintain": True, "triage": False}},
        ):
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                f"repos/{REPO}": valid_meta,
            }
            with self.subTest(valid_meta=valid_meta), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["repository_metadata"], valid_meta)

    def test_malformed_or_absent_repository_metadata_fails_closed(self):
        bad_metas = (
            None,
            {},
            {"default_branch": None, "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "   ", "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": 123, "private": False, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "main", "private": "false", "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "main", "private": None, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "main", "private": 0, "permissions": {"pull": True, "push": True, "admin": False}},
            {"default_branch": "main", "private": False, "permissions": "not-a-dict"},
            {"default_branch": "main", "private": False, "permissions": {}},
            {"default_branch": "main", "private": False, "permissions": {"push": True, "admin": False}},
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "admin": False}},
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True}},
            {"default_branch": "main", "private": False, "permissions": {"pull": "true", "push": True, "admin": False}},
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False, "maintain": "true"}},
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False, "unknown": True}},
            {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": None}},
            {"default_branch": "main", "private": False},
            {"default_branch": "main", "permissions": {"pull": True, "push": True, "admin": False}},
            {"private": False, "permissions": {"pull": True, "push": True, "admin": False}},
        )
        for bad_meta in bad_metas:
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                f"repos/{REPO}": bad_meta,
            }
            with self.subTest(bad_meta=bad_meta), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["repository_metadata"], "UNKNOWN")

    def test_valid_workflow_permissions_succeeds(self):
        for valid_wf in (
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
            {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
        ):
            workflow_path = f"repos/{REPO}/actions/permissions/workflow"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                workflow_path: valid_wf,
            }
            with self.subTest(valid_wf=valid_wf), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["workflow_permissions"], valid_wf)

    def test_malformed_or_absent_workflow_permissions_fails_closed(self):
        bad_wfs = (
            None,
            {},
            {"can_approve_pull_request_reviews": False},
            {"default_workflow_permissions": "read"},
            {"default_workflow_permissions": "none", "can_approve_pull_request_reviews": False},
            {"default_workflow_permissions": "invalid", "can_approve_pull_request_reviews": False},
            {"default_workflow_permissions": 123, "can_approve_pull_request_reviews": False},
            {"default_workflow_permissions": None, "can_approve_pull_request_reviews": False},
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": "false"},
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": 0},
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": None},
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False, "extra": True},
            "not-a-dict",
        )
        for bad_wf in bad_wfs:
            workflow_path = f"repos/{REPO}/actions/permissions/workflow"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                workflow_path: bad_wf,
            }
            with self.subTest(bad_wf=bad_wf), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["workflow_permissions"], "UNKNOWN")

    def test_valid_branch_protection_succeeds(self):
        for valid_bp in (
            VALID_BRANCH_PROTECTION,
            {
                "required_pull_request_reviews": {"required_approving_review_count": 2, "dismiss_stale_reviews": True, "require_code_owner_reviews": True, "require_last_push_approval": False},
                "required_status_checks": {"strict": False, "contexts": ["build"]},
                "enforce_admins": {"enabled": True},
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False, "require_last_push_approval": True},
                "required_status_checks": {"strict": True, "checks": [{"context": "ci", "app_id": 123}]},
                "enforce_admins": {"enabled": False, "url": "https://api.github.com/..."},
                "required_linear_history": {"enabled": True},
                "allow_force_pushes": False,
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False, "require_last_push_approval": False},
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}], "contexts": ["ci"]},
                "enforce_admins": {"enabled": True},
            },
        ):
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: valid_bp,
            }
            with self.subTest(valid_bp=valid_bp), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["branch_protection"], valid_bp)

    def test_malformed_or_absent_branch_protection_fails_closed(self):
        bad_bps = (
            {},
            None,
            # Partial shapes demonstrated in defect description
            {"enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1}},
            {"required_status_checks": {"strict": True, "checks": [{"context": "ci"}]}},
            # Missing required nested fields or subsections
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1}, # missing dismiss_stale_reviews, require_code_owner_reviews
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
                "enforce_admins": {"enabled": True},
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False}, # missing require_last_push_approval
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
                "enforce_admins": {"enabled": True},
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False, "require_last_push_approval": "true"}, # malformed type
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
                "enforce_admins": {"enabled": True},
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False, "require_last_push_approval": None}, # malformed type
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
                "enforce_admins": {"enabled": True},
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False, "require_last_push_approval": False},
                "required_status_checks": {"checks": [{"context": "ci"}]}, # missing strict
                "enforce_admins": {"enabled": True},
            },
            {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
                "enforce_admins": {}, # missing enabled
            },
            {"required_pull_request_reviews": {"required_approving_review_count": "1", "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {},
             "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": "yes", "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": "true", "checks": [{"context": "ci"}]},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": "not-a-list"},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": [{"context": ""}]},
             "enforce_admins": {"enabled": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
             "enforce_admins": {"enabled": "true"}},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
             "enforce_admins": True},
            {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": False, "require_code_owner_reviews": False},
             "required_status_checks": {"strict": True, "checks": [{"context": "ci"}]},
             "enforce_admins": {"enabled": True},
             "unknown_control": True},
            "not-a-dict",
        )
        for bad_bp in bad_bps:
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: bad_bp,
            }
            with self.subTest(bad_bp=bad_bp), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["branch_protection"], "UNKNOWN")

    def test_mismatched_status_checks_fail_closed(self):
        for bad_bp in (
            {
                **VALID_BRANCH_PROTECTION,
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}], "contexts": ["other"]},
            },
            {
                **VALID_BRANCH_PROTECTION,
                "required_status_checks": {"strict": True, "checks": [{"context": "ci"}], "contexts": ["ci", "other"]},
            },
        ):
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: bad_bp,
            }
            with self.subTest(bad_bp=bad_bp), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["branch_protection"], "UNKNOWN")

    def test_branch_protection_status_check_app_id_valid_values(self):
        for app_id_val in (
            None,
            1,
            15368,
            -1,
        ):
            check_entry = {"context": "ci"}
            if app_id_val is not None:
                check_entry["app_id"] = app_id_val
            valid_bp = {
                **VALID_BRANCH_PROTECTION,
                "required_status_checks": {
                    "strict": True,
                    "checks": [check_entry],
                }
            }
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: valid_bp,
            }
            with self.subTest(app_id_val=app_id_val), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["branch_protection"], valid_bp)

    def test_branch_protection_status_check_app_id_invalid_values(self):
        for bad_app_id in (
            0,
            -2,
            -10,
            True,
            False,
            "15368",
            "-1",
            "0",
            15368.0,
            [],
            {},
        ):
            bad_bp = {
                **VALID_BRANCH_PROTECTION,
                "required_status_checks": {
                    "strict": True,
                    "checks": [{"context": "ci", "app_id": bad_app_id}],
                }
            }
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: bad_bp,
            }
            with self.subTest(bad_app_id=bad_app_id), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["branch_protection"], "UNKNOWN")

    def test_valid_branch_protection_nested_restrictions_succeeds(self):
        valid_bp = {
            **VALID_BRANCH_PROTECTION,
            "required_pull_request_reviews": {
                **VALID_BRANCH_PROTECTION["required_pull_request_reviews"],
                "dismissal_restrictions": {
                    "users": [{"id": 1, "login": "user1"}],
                    "teams": [{"id": 2, "slug": "team1"}],
                    "apps": [{"id": 3, "slug": "app1"}],
                    "url": "https://api.github.com/...",
                },
                "bypass_pull_request_allowances": {
                    "users": [],
                    "teams": [],
                    "apps": [],
                },
            },
            "restrictions": {
                "users": [{"id": 4, "login": "user2"}],
                "teams": [],
                "apps": [],
            },
        }
        bp_path = f"repos/{REPO}/branches/main/protection"
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            bp_path: valid_bp,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["branch_protection"], valid_bp)

    def test_malformed_branch_protection_nested_restrictions_fail_closed(self):
        base_pr = VALID_BRANCH_PROTECTION["required_pull_request_reviews"]
        bad_restrictions_cases = [
            # dismissal_restrictions not a dict
            {**VALID_BRANCH_PROTECTION, "required_pull_request_reviews": {**base_pr, "dismissal_restrictions": "not-a-dict"}},
            # bypass_pull_request_allowances missing users
            {**VALID_BRANCH_PROTECTION, "required_pull_request_reviews": {**base_pr, "bypass_pull_request_allowances": {"teams": [], "apps": []}}},
            # restrictions users not a list
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": "not-a-list", "teams": [], "apps": []}},
            # user missing id
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [{"login": "user"}], "teams": [], "apps": []}},
            # user missing login
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [{"id": 1}], "teams": [], "apps": []}},
            # user id invalid
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [{"id": 0, "login": "user"}], "teams": [], "apps": []}},
            # team missing slug
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [], "teams": [{"id": 1}], "apps": []}},
            # app missing slug/name
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [], "teams": [], "apps": [{"id": 1}]}},
            # unexpected key in restriction object
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [], "teams": [], "apps": [], "unexpected": True}},
        ]
        for bad_bp in bad_restrictions_cases:
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: bad_bp,
            }
            with self.subTest(bad_bp=bad_bp), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["branch_protection"], "UNKNOWN")

    def test_present_null_nested_restrictions_and_app_without_slug_fail_closed(self):
        base_pr = VALID_BRANCH_PROTECTION["required_pull_request_reviews"]
        bad_cases = [
            {**VALID_BRANCH_PROTECTION, "required_pull_request_reviews": {**base_pr, "dismissal_restrictions": None}},
            {**VALID_BRANCH_PROTECTION, "required_pull_request_reviews": {**base_pr, "bypass_pull_request_allowances": None}},
            {**VALID_BRANCH_PROTECTION, "restrictions": {"users": [], "teams": [], "apps": [{"id": 3, "name": "app1"}]}},
        ]
        for bad_bp in bad_cases:
            bp_path = f"repos/{REPO}/branches/main/protection"
            responses = {
                **BASE_RESPONSES,
                ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
                bp_path: bad_bp,
            }
            with self.subTest(bad_bp=bad_bp), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertFalse(result["known"])
                self.assertEqual(result["branch_protection"], "UNKNOWN")

    def test_absent_optional_nested_sections_and_top_level_restrictions_null_succeed(self):
        valid_bp = {
            **VALID_BRANCH_PROTECTION,
            "restrictions": None,
        }
        bp_path = f"repos/{REPO}/branches/main/protection"
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            bp_path: valid_bp,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["branch_protection"], valid_bp)

    def test_missing_gh_cli_fails_closed_snapshot(self):
        with patch("task_authority_lab.collector.github.subprocess.run",
                   side_effect=FileNotFoundError("No such file or directory: 'gh'")):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["branch_protection"], "UNKNOWN")
        self.assertEqual(result["rulesets"], "UNKNOWN")
        self.assertEqual(result["workflow_permissions"], "UNKNOWN")
        self.assertEqual(result["environments"], "UNKNOWN")
        self.assertEqual(result["repository_metadata"], "UNKNOWN")
        self.assertEqual(result["repository"], REPO)
        self.assertEqual(result["base_branch"], "main")
        self.assertEqual(result["source"], "github_api_via_gh")
        self.assertIn("snapshot_at", result)
        self.assertIn("integrity_hash", result)

    def test_launch_denied_gh_cli_fails_closed_snapshot(self):
        with patch("task_authority_lab.collector.github.subprocess.run",
                   side_effect=PermissionError("Permission denied: 'gh'")):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["branch_protection"], "UNKNOWN")
        self.assertEqual(result["rulesets"], "UNKNOWN")
        self.assertEqual(result["workflow_permissions"], "UNKNOWN")
        self.assertEqual(result["environments"], "UNKNOWN")
        self.assertEqual(result["repository_metadata"], "UNKNOWN")
        self.assertEqual(result["repository"], REPO)
        self.assertEqual(result["base_branch"], "main")
        self.assertEqual(result["source"], "github_api_via_gh")
        self.assertIn("snapshot_at", result)
        self.assertIn("integrity_hash", result)

    def test_timeout_gh_cli_fails_closed_snapshot(self):
        with patch("task_authority_lab.collector.github.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(["gh", "api"], 10)):
            result = snapshot(REPO, "main")
        self.assertFalse(result["known"])
        self.assertEqual(result["branch_protection"], "UNKNOWN")
        self.assertEqual(result["rulesets"], "UNKNOWN")
        self.assertEqual(result["workflow_permissions"], "UNKNOWN")
        self.assertEqual(result["environments"], "UNKNOWN")
        self.assertEqual(result["repository_metadata"], "UNKNOWN")
        self.assertEqual(result["repository"], REPO)
        self.assertEqual(result["base_branch"], "main")
        self.assertEqual(result["source"], "github_api_via_gh")
        self.assertIn("snapshot_at", result)
        self.assertIn("integrity_hash", result)

    def test_valid_baseline_succeeds_snapshot(self):
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            RULESETS_PATH: [[]],
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["branch_protection"], VALID_BRANCH_PROTECTION)
        self.assertEqual(result["rulesets"], [])
        self.assertEqual(result["workflow_permissions"], {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False})
        self.assertEqual(result["environments"], {"total_count": 0, "environments": []})
        self.assertEqual(result["repository_metadata"], {"default_branch": "main", "private": False, "permissions": {"pull": True, "push": True, "admin": False}})
        self.assertIn("integrity_hash", result)


if __name__ == "__main__":
    unittest.main()
