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


def _valid_property_selector(cond_val: Any, *, allow_source: bool) -> bool:
    if not isinstance(cond_val, dict):
        return False
    if not set(cond_val.keys()).issubset({"include", "exclude"}):
        return False
    include = cond_val.get("include")
    exclude = cond_val.get("exclude")
    if include is not None and not isinstance(include, list):
        return False
    if exclude is not None and not isinstance(exclude, list):
        return False
    if (include is None or not include) and (exclude is None or not exclude):
        return False
    for items in (include, exclude):
        if items is None:
            continue
        for item in items:
            if not isinstance(item, dict):
                return False
            allowed_keys = {"name", "property_values", "source"} if allow_source else {"name", "property_values"}
            if not set(item.keys()).issubset(allowed_keys):
                return False
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                return False
            prop_values = item.get("property_values")
            if not isinstance(prop_values, list) or any(not isinstance(x, str) for x in prop_values):
                return False
            if allow_source:
                if "source" in item:
                    source = item.get("source")
                    if not isinstance(source, str) or source not in {"custom", "system"}:
                        return False
    return True


def _valid_ruleset_detail(detail: Any, summary: dict[str, Any]) -> bool:
    if not isinstance(detail, dict):
        return False
    identifier = detail.get("id")
    if type(identifier) is not int or identifier <= 0 or identifier != summary.get("id"):
        return False
    name = detail.get("name")
    if not isinstance(name, str) or not name.strip() or name != summary.get("name"):
        return False
    target = detail.get("target")
    if not isinstance(target, str) or target not in {"branch", "tag", "repository"}:
        return False
    source_type = detail.get("source_type")
    if not isinstance(source_type, str) or source_type not in {"Repository", "Organization", "Enterprise"} or source_type != summary.get("source_type"):
        return False
    source = detail.get("source")
    if not isinstance(source, str) or not source.strip() or source != summary.get("source"):
        return False
    enforcement = detail.get("enforcement")
    if enforcement not in {"active", "evaluate", "disabled"} or enforcement != summary.get("enforcement"):
        return False
    if "bypass_actors" not in detail:
        return False
    bypass_actors = detail.get("bypass_actors")
    if not isinstance(bypass_actors, list):
        return False
    for actor in bypass_actors:
        if not isinstance(actor, dict):
            return False
        actor_type = actor.get("actor_type")
        if not isinstance(actor_type, str) or not actor_type.strip():
            return False
        bypass_mode = actor.get("bypass_mode")
        if not isinstance(bypass_mode, str) or not bypass_mode.strip():
            return False
        actor_id = actor.get("actor_id")
        if actor_id is not None and not isinstance(actor_id, int):
            return False
    conditions = detail.get("conditions")
    if not isinstance(conditions, dict) or not conditions:
        return False
    has_ref_name = False
    repo_selectors = []
    org_selectors = []
    for cond_key, cond_val in conditions.items():
        if not isinstance(cond_val, dict):
            return False
        if cond_key == "ref_name":
            if not set(cond_val.keys()).issubset({"include", "exclude"}):
                return False
            include = cond_val.get("include")
            exclude = cond_val.get("exclude")
            if not isinstance(include, list) or not include or any(not isinstance(x, str) or not x.strip() for x in include):
                return False
            if not isinstance(exclude, list) or any(not isinstance(x, str) for x in exclude):
                return False
            has_ref_name = True
        elif cond_key in {"repository_name", "repository_id", "repository_property"}:
            if cond_key == "repository_name":
                if not set(cond_val.keys()).issubset({"include", "exclude"}):
                    return False
                include = cond_val.get("include")
                exclude = cond_val.get("exclude")
                if not isinstance(include, list) or not include or any(not isinstance(x, str) or not x.strip() for x in include):
                    return False
                if not isinstance(exclude, list) or any(not isinstance(x, str) for x in exclude):
                    return False
            elif cond_key == "repository_id":
                if not set(cond_val.keys()).issubset({"repository_ids"}):
                    return False
                repo_ids = cond_val.get("repository_ids")
                if not isinstance(repo_ids, list) or not repo_ids or any(type(x) is not int or x <= 0 for x in repo_ids):
                    return False
            elif cond_key == "repository_property":
                if not _valid_property_selector(cond_val, allow_source=True):
                    return False
            repo_selectors.append(cond_key)
        elif cond_key in {"organization_id", "organization_name", "organization_property"}:
            if cond_key == "organization_id":
                if not set(cond_val.keys()).issubset({"organization_ids"}):
                    return False
                org_ids = cond_val.get("organization_ids")
                if not isinstance(org_ids, list) or not org_ids or any(type(x) is not int or x <= 0 for x in org_ids):
                    return False
            elif cond_key == "organization_name":
                if not set(cond_val.keys()).issubset({"include", "exclude"}):
                    return False
                include = cond_val.get("include")
                exclude = cond_val.get("exclude")
                if not isinstance(include, list) or not include or any(not isinstance(x, str) or not x.strip() for x in include):
                    return False
                if not isinstance(exclude, list) or any(not isinstance(x, str) for x in exclude):
                    return False
            elif cond_key == "organization_property":
                if not _valid_property_selector(cond_val, allow_source=False):
                    return False
            org_selectors.append(cond_key)
        else:
            return False

    num_repo_selectors = len(repo_selectors)
    num_org_selectors = len(org_selectors)
    has_valid_targeting = False
    if target in {"branch", "tag"}:
        if source_type == "Repository":
            if has_ref_name and num_repo_selectors == 0 and num_org_selectors == 0:
                has_valid_targeting = True
        elif source_type == "Organization":
            if has_ref_name and num_repo_selectors == 1 and num_org_selectors == 0:
                has_valid_targeting = True
        elif source_type == "Enterprise":
            if has_ref_name and num_org_selectors == 1 and num_repo_selectors == 1 and repo_selectors[0] in {"repository_name", "repository_property"}:
                has_valid_targeting = True
    elif target == "repository":
        if source_type == "Repository":
            if not has_ref_name and num_repo_selectors == 1 and num_org_selectors == 0:
                has_valid_targeting = True
        elif source_type == "Organization":
            if not has_ref_name and num_repo_selectors == 1 and num_org_selectors == 0:
                has_valid_targeting = True
        elif source_type == "Enterprise":
            if not has_ref_name and num_org_selectors == 1 and num_repo_selectors == 1 and repo_selectors[0] in {"repository_name", "repository_property"}:
                has_valid_targeting = True

    if not has_valid_targeting:
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
        if rule_type == "pull_request":
            if not isinstance(parameters, dict):
                return False
            approvals = parameters.get("required_approving_review_count")
            if type(approvals) is not int or approvals < 0:
                return False
            last_push = parameters.get("require_last_push_approval")
            if type(last_push) is not bool:
                return False
            dismiss_stale = parameters.get("dismiss_stale_reviews_on_push")
            if type(dismiss_stale) is not bool:
                return False
            code_owner = parameters.get("require_code_owner_review")
            if type(code_owner) is not bool:
                return False
            thread_res = parameters.get("required_review_thread_resolution")
            if type(thread_res) is not bool:
                return False
        elif rule_type == "required_status_checks":
            if not isinstance(parameters, dict):
                return False
            status_checks = parameters.get("required_status_checks")
            if not isinstance(status_checks, list):
                return False
            for check in status_checks:
                if not isinstance(check, dict):
                    return False
                context = check.get("context")
                if not isinstance(context, str) or not context.strip():
                    return False
                integration_id = check.get("integration_id")
                if integration_id is not None and type(integration_id) is not int:
                    return False
            strict = parameters.get("strict_required_status_checks_policy")
            if type(strict) is not bool:
                return False
        elif rule_type == "required_linear_history":
            if parameters is not None and not isinstance(parameters, dict):
                return False
        else:
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


def _complete_repository_metadata(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    default_branch = value.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch.strip():
        return False
    private = value.get("private")
    if type(private) is not bool:
        return False
    permissions = value.get("permissions")
    if not isinstance(permissions, dict):
        return False
    core_permissions = {"pull", "push", "admin"}
    if not core_permissions.issubset(permissions.keys()):
        return False
    allowed_permissions = {"pull", "push", "admin", "maintain", "triage"}
    if not set(permissions.keys()).issubset(allowed_permissions):
        return False
    if any(type(v) is not bool for v in permissions.values()):
        return False
    return True


def _complete_workflow_permissions(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    required_keys = {"default_workflow_permissions", "can_approve_pull_request_reviews"}
    if not required_keys.issubset(value.keys()):
        return False
    allowed_keys = {"default_workflow_permissions", "can_approve_pull_request_reviews"}
    if not set(value.keys()).issubset(allowed_keys):
        return False
    default_perms = value.get("default_workflow_permissions")
    if not isinstance(default_perms, str) or default_perms not in {"read", "write"}:
        return False
    can_approve = value.get("can_approve_pull_request_reviews")
    if type(can_approve) is not bool:
        return False
    return True


def _valid_restriction_object(obj: Any) -> bool:
    if obj is None:
        return True
    if not isinstance(obj, dict):
        return False
    allowed_keys = {"users", "teams", "apps", "url", "users_url", "teams_url", "apps_url"}
    if not set(obj.keys()).issubset(allowed_keys):
        return False
    required_keys = {"users", "teams", "apps"}
    if not required_keys.issubset(obj.keys()):
        return False

    users = obj.get("users")
    if not isinstance(users, list):
        return False
    for user in users:
        if not isinstance(user, dict):
            return False
        uid = user.get("id")
        if type(uid) is not int or uid <= 0:
            return False
        login = user.get("login")
        if not isinstance(login, str) or not login.strip():
            return False

    teams = obj.get("teams")
    if not isinstance(teams, list):
        return False
    for team in teams:
        if not isinstance(team, dict):
            return False
        tid = team.get("id")
        if type(tid) is not int or tid <= 0:
            return False
        slug = team.get("slug")
        if not isinstance(slug, str) or not slug.strip():
            return False

    apps = obj.get("apps")
    if not isinstance(apps, list):
        return False
    for app in apps:
        if not isinstance(app, dict):
            return False
        aid = app.get("id")
        if type(aid) is not int or aid <= 0:
            return False
        aslug = app.get("slug")
        aname = app.get("name")
        if not ((isinstance(aslug, str) and aslug.strip()) or (isinstance(aname, str) and aname.strip())):
            return False

    for url_key in ("url", "users_url", "teams_url", "apps_url"):
        if url_key in obj and obj[url_key] is not None and not isinstance(obj[url_key], str):
            return False

    return True


def _complete_branch_protection(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    allowed_keys = {
        "url",
        "required_status_checks",
        "required_pull_request_reviews",
        "enforce_admins",
        "required_signatures",
        "restrictions",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
        "block_creations",
        "required_conversation_resolution",
        "lock_branch",
        "allow_fork_syncing",
        "name",
        "protected",
        "protection_url",
    }
    if not set(value.keys()).issubset(allowed_keys):
        return False

    required_core_keys = {"required_pull_request_reviews", "required_status_checks", "enforce_admins"}
    if not required_core_keys.issubset(value.keys()):
        return False

    pr = value.get("required_pull_request_reviews")
    if not isinstance(pr, dict):
        return False
    approvals = pr.get("required_approving_review_count")
    if type(approvals) is not int or approvals < 0:
        return False
    dismiss_stale = pr.get("dismiss_stale_reviews")
    if type(dismiss_stale) is not bool:
        return False
    code_owner = pr.get("require_code_owner_reviews")
    if type(code_owner) is not bool:
        return False
    last_push = pr.get("require_last_push_approval")
    if type(last_push) is not bool:
        return False
    for k in ("required_review_thread_resolution",):
        if k in pr and type(pr[k]) is not bool:
            return False
    for k in ("dismissal_restrictions", "bypass_pull_request_allowances"):
        if k in pr and not _valid_restriction_object(pr[k]):
            return False
    if "url" in pr and pr["url"] is not None and not isinstance(pr["url"], str):
        return False

    sc = value.get("required_status_checks")
    if not isinstance(sc, dict):
        return False
    strict = sc.get("strict")
    if type(strict) is not bool:
        return False
    checks = sc.get("checks")
    if checks is not None:
        if not isinstance(checks, list):
            return False
        for check in checks:
            if not isinstance(check, dict):
                return False
            context = check.get("context")
            if not isinstance(context, str) or not context.strip():
                return False
            app_id = check.get("app_id")
            if app_id is not None and type(app_id) is not int:
                return False
    contexts = sc.get("contexts")
    if contexts is not None:
        if not isinstance(contexts, list):
            return False
        for ctx in contexts:
            if not isinstance(ctx, str) or not ctx.strip():
                return False
    if checks is None and contexts is None:
        return False

    ea = value.get("enforce_admins")
    if not isinstance(ea, dict):
        return False
    enabled = ea.get("enabled")
    if type(enabled) is not bool:
        return False
    if "url" in ea and ea["url"] is not None and not isinstance(ea["url"], str):
        return False

    for flag_key in (
        "required_signatures",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
        "block_creations",
        "required_conversation_resolution",
        "lock_branch",
        "allow_fork_syncing",
    ):
        if flag_key in value:
            flag_val = value.get(flag_key)
            if isinstance(flag_val, dict):
                en = flag_val.get("enabled")
                if type(en) is not bool:
                    return False
            elif type(flag_val) is not bool:
                return False

    if "restrictions" in value:
        res = value.get("restrictions")
        if not _valid_restriction_object(res):
            return False

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
            if detail is None or not _valid_ruleset_detail(detail, summary):
                all_valid = False
                break
            detailed_rulesets.append(detail)
        if all_valid:
            rulesets = detailed_rulesets
    workflow_permissions = _api(f"repos/{repo}/actions/permissions/workflow")
    environments = _api(f"repos/{repo}/environments?per_page=100&page=1")
    repo_meta = _api(f"repos/{repo}")
    environments_known = _complete_environments(environments)
    repo_meta_known = _complete_repository_metadata(repo_meta)
    workflow_permissions_known = _complete_workflow_permissions(workflow_permissions)
    branch_known = _complete_branch_protection(branch)
    output = {
        "repository": repo,
        "base_branch": base_branch,
        "snapshot_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "github_api_via_gh",
        "branch_protection": branch if branch_known else "UNKNOWN",
        "rulesets": rulesets if rulesets is not None else "UNKNOWN",
        "workflow_permissions": workflow_permissions if workflow_permissions_known else "UNKNOWN",
        "environments": environments if environments_known else "UNKNOWN",
        "repository_metadata": {
            "default_branch": repo_meta.get("default_branch"),
            "private": repo_meta.get("private"),
            "permissions": repo_meta.get("permissions"),
        } if repo_meta_known else "UNKNOWN",
    }
    output["known"] = all(output[key] != "UNKNOWN" for key in ("branch_protection", "rulesets", "workflow_permissions", "environments", "repository_metadata"))
    output["integrity_hash"] = sha256_json(output)
    return output
