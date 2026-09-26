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


def _api(path: str, *, paginate: bool = False) -> dict[str, Any] | list[Any] | None:
    command = ["gh", "api"]
    if paginate:
        command.extend(["--paginate", "--slurp"])
    command.append(path)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _complete_rulesets_summary(pages: Any) -> list[dict[str, Any]] | None:
    # --slurp wraps every API page in an outer list, including one empty page.
    if not isinstance(pages, list) or not pages:
        return None
    rulesets: list[dict[str, Any]] = []
    identifiers: set[int] = set()
    for page in pages:
        if not isinstance(page, list) or len(page) > 100:
            return None
        for entry in page:
            if not isinstance(entry, dict):
                return None
            identifier = entry.get("id")
            if (type(identifier) is not int or identifier <= 0 or identifier in identifiers
                    or not isinstance(entry.get("name"), str) or not entry["name"].strip()
                    or not isinstance(entry.get("source_type"), str) or not entry["source_type"]
                    or not isinstance(entry.get("source"), str) or not entry["source"]
                    or entry.get("enforcement") not in {"active", "evaluate", "disabled"}):
                return None
            identifiers.add(identifier)
            rulesets.append(entry)
    return rulesets


def _valid_ruleset_detail(detail: Any, expected_id: int) -> bool:
    if not isinstance(detail, dict):
        return False
    identifier = detail.get("id")
    if type(identifier) is not int or identifier <= 0 or identifier != expected_id:
        return False
    name = detail.get("name")
    if not isinstance(name, str) or not name.strip():
        return False
    target = detail.get("target")
    if not isinstance(target, str) or not target.strip():
        return False
    source_type = detail.get("source_type")
    if not isinstance(source_type, str) or not source_type.strip():
        return False
    source = detail.get("source")
    if not isinstance(source, str) or not source.strip():
        return False
    enforcement = detail.get("enforcement")
    if enforcement not in {"active", "evaluate", "disabled"}:
        return False
    conditions = detail.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if ref_name is not None:
        if not isinstance(ref_name, dict):
            return False
        include = ref_name.get("include")
        exclude = ref_name.get("exclude")
        if include is not None and (not isinstance(include, list) or any(not isinstance(x, str) for x in include)):
            return False
        if exclude is not None and (not isinstance(exclude, list) or any(not isinstance(x, str) for x in exclude)):
            return False

    rules = detail.get("rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            return False
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type.strip():
            return False
        parameters = rule.get("parameters")
        if parameters is not None:
            if not isinstance(parameters, dict):
                return False
            if rule_type == "pull_request":
                approvals = parameters.get("required_approving_review_count")
                if approvals is not None:
                    if type(approvals) is not int or approvals < 0:
                        return False
                for param_key in ("dismiss_stale_reviews_on_push", "require_code_owner_review", "required_review_thread_resolution"):
                    val = parameters.get(param_key)
                    if val is not None and type(val) is not bool:
                        return False
            for k, v in parameters.items():
                if v is None and k in {"required_approving_review_count", "required_status_checks"}:
                    return False
    return True


def _valid_protection_rule(rule: Any) -> bool:
    if not isinstance(rule, dict) or type(rule.get("id")) is not int or rule["id"] <= 0:
        return False
    kind = rule.get("type")
    if kind == "wait_timer":
        return type(rule.get("wait_timer")) is int and rule["wait_timer"] >= 0
    if kind == "branch_policy":
        return True
    if kind == "required_reviewers":
        if type(rule.get("prevent_self_review")) is not bool:
            return False
        reviewers = rule.get("reviewers")
        if not isinstance(reviewers, list) or not reviewers:
            return False
        for entry in reviewers:
            if not isinstance(entry, dict) or not isinstance(entry.get("reviewer"), dict):
                return False
            subject = entry["reviewer"]
            if type(subject.get("id")) is not int or subject["id"] <= 0:
                return False
            if entry.get("type") == "User":
                if not isinstance(subject.get("login"), str) or not subject["login"]:
                    return False
            elif entry.get("type") == "Team":
                if not isinstance(subject.get("slug"), str) or not subject["slug"]:
                    return False
            else:
                return False
        return True
    # Unknown protection-rule types need explicit interpretation before known=true.
    return False


def _complete_environments(value: Any) -> bool:
    if not isinstance(value, dict) or type(value.get("total_count")) is not int:
        return False
    count = value["total_count"]
    environments = value.get("environments")
    # We request one page of up to 100. A larger or truncated set is unknown.
    if count < 0 or count > 100 or not isinstance(environments, list) or len(environments) != count:
        return False
    names: set[str] = set()
    identifiers: set[int] = set()
    for entry in environments:
        if not isinstance(entry, dict):
            return False
        identifier = entry.get("id")
        name = entry.get("name")
        rules = entry.get("protection_rules")
        policy = entry.get("deployment_branch_policy", ...)
        if (type(identifier) is not int or identifier <= 0
                or not isinstance(name, str) or not name.strip()
                or identifier in identifiers or name.casefold() in names
                or not isinstance(rules, list) or policy is ...):
            return False
        if policy is not None and (
            not isinstance(policy, dict)
            or type(policy.get("protected_branches")) is not bool
            or type(policy.get("custom_branch_policies")) is not bool
        ):
            return False
        # This endpoint exposes the flag, not the custom branch patterns.
        if policy is not None and policy["custom_branch_policies"]:
            return False
        if any(not _valid_protection_rule(rule) for rule in rules):
            return False
        names.add(name.casefold())
        identifiers.add(identifier)
    return True


def snapshot(repo: str, base_branch: str) -> dict[str, Any]:
    if not repo or "/" not in repo or not base_branch:
        raise ValueError("repo must be owner/name and base branch must be given")
    branch = _api(f"repos/{repo}/branches/{base_branch}/protection")
    ruleset_pages = _api(f"repos/{repo}/rulesets?includes_parents=true&per_page=100", paginate=True)
    rulesets_summary = _complete_rulesets_summary(ruleset_pages)
    rulesets = None
    if rulesets_summary is not None:
        detailed_rulesets = []
        all_valid = True
        for summary in rulesets_summary:
            identifier = summary["id"]
            detail = _api(f"repos/{repo}/rulesets/{identifier}?includes_parents=true")
            if detail is None or not _valid_ruleset_detail(detail, identifier):
                all_valid = False
                break
            detailed_rulesets.append(detail)
        if all_valid:
            rulesets = detailed_rulesets
    workflow_permissions = _api(f"repos/{repo}/actions/permissions/workflow")
    environments = _api(f"repos/{repo}/environments?per_page=100&page=1")
    repo_meta = _api(f"repos/{repo}")
    environments_known = _complete_environments(environments)
    output = {
        "repository": repo,
        "base_branch": base_branch,
        "snapshot_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "github_api_via_gh",
        "branch_protection": branch if branch is not None else "UNKNOWN",
        "rulesets": rulesets if rulesets is not None else "UNKNOWN",
        "workflow_permissions": workflow_permissions if workflow_permissions is not None else "UNKNOWN",
        "environments": environments if environments_known else "UNKNOWN",
        "repository_metadata": {
            "default_branch": repo_meta.get("default_branch"),
            "private": repo_meta.get("private"),
            "permissions": repo_meta.get("permissions"),
        } if isinstance(repo_meta, dict) else "UNKNOWN",
    }
    output["known"] = all(output[key] != "UNKNOWN" for key in ("branch_protection", "rulesets", "workflow_permissions", "environments", "repository_metadata"))
    output["integrity_hash"] = sha256_json(output)
    return output
