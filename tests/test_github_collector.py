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

BASE_RESPONSES = {
    f"repos/{REPO}/branches/main/protection": {"required_pull_request_reviews": {"required_approving_review_count": 1}},
    RULESETS_PATH: [[{"id": 41, "name": "one", "source_type": "Repository", "source": REPO, "enforcement": "active"}]],
    RULESET_41_PATH: VALID_RULESET_41,
    RULESET_42_PATH: VALID_RULESET_42,
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
    def test_rulesets_request_uses_all_pages(self):
        with patch("task_authority_lab.collector.github.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, "[[],[]]", "")) as run:
            self.assertEqual(_api(RULESETS_PATH, paginate=True), [[], []])
        run.assert_called_once_with(
            ["gh", "api", "--paginate", "--slurp", RULESETS_PATH],
            capture_output=True, text=True,
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
            [{"actor_type": "Integration", "bypass_mode": ""}],
            [{"actor_type": "Integration", "bypass_mode": "always", "actor_id": "not-int"}],
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
                f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"push": True}},
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
            f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"push": True}},
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
                f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"push": True}},
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
                f"repos/{REPO}": {"default_branch": "main", "private": False, "permissions": {"push": True}},
            }
            with self.subTest(detail=good_detail), patch(
                "task_authority_lab.collector.github._api",
                side_effect=lambda route, **kwargs: responses_valid.get(route),
            ):
                result = snapshot(REPO, "main")
                self.assertTrue(result["known"])
                self.assertEqual(result["rulesets"], [good_detail])

    def test_valid_repository_metadata_succeeds(self):
        valid_meta = {"default_branch": "main", "private": False, "permissions": {"push": True, "admin": False}}
        responses = {
            **BASE_RESPONSES,
            ENVIRONMENTS_PATH: {"total_count": 0, "environments": []},
            f"repos/{REPO}": valid_meta,
        }
        with patch("task_authority_lab.collector.github._api",
                   side_effect=lambda route, **kwargs: responses.get(route)):
            result = snapshot(REPO, "main")
        self.assertTrue(result["known"])
        self.assertEqual(result["repository_metadata"], valid_meta)

    def test_malformed_or_absent_repository_metadata_fails_closed(self):
        bad_metas = (
            None,
            {},
            {"default_branch": None, "private": False, "permissions": {"push": True}},
            {"default_branch": "", "private": False, "permissions": {"push": True}},
            {"default_branch": "   ", "private": False, "permissions": {"push": True}},
            {"default_branch": 123, "private": False, "permissions": {"push": True}},
            {"default_branch": "main", "private": "false", "permissions": {"push": True}},
            {"default_branch": "main", "private": None, "permissions": {"push": True}},
            {"default_branch": "main", "private": 0, "permissions": {"push": True}},
            {"default_branch": "main", "private": False, "permissions": "not-a-dict"},
            {"default_branch": "main", "private": False, "permissions": {"push": "true"}},
            {"default_branch": "main", "private": False, "permissions": {"push": 1}},
            {"default_branch": "main", "private": False, "permissions": {"push": None}},
            {"default_branch": "main", "private": False},
            {"default_branch": "main", "permissions": {"push": True}},
            {"private": False, "permissions": {"push": True}},
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


if __name__ == "__main__":
    unittest.main()
