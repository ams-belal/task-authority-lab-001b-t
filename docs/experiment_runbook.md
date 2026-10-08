# Product Test 001B-T runbook

## Activation

1. Select a real repository and agent workflow. Verify a human review/merge or
   staging gate is enforced. Record exact native rule/version and approver.
2. Establish separate agent, recorder, approver, and executor identities. Verify
   the agent cannot merge, approve, or deploy and holds no standing privileged
   credential. Do not print credential values.
3. Freeze repository-specific delegation, Policy v0 source hash, eligibility
   rule, and task-arrival start. Keep the human gate operational.
4. Enroll the next 20 genuine eligible tasks in arrival order. Record every
   failure and exclusion. A rolling append-only enrollment log prevents later
   selection based on outcomes; freeze and hash the final manifest.

## Per proposal

1. Confirm an actual gate is **pending** and required by an active rule.
2. Capture task, delegation, agent events, exact branch/commit, check artifacts,
   downstream triggers, and native controls. Verify all are pre-effect.
3. Build a request JSON from separately sourced evidence. Run
   `python3 -m task_authority_lab.cli shadow request.json experiments/001b_t/decisions`.
4. Verify the receipt with `python3 -m task_authority_lab.cli verify <decision-directory>`.
   The receipt must say `VALID_CANDIDATE`, and an operator must additionally
   verify complete native controls and actual useful agent work. A fixture or
   partial snapshot does not satisfy M0.
5. Hide the shadow result from the approver. The real human gate proceeds. Only
   after their outcome is recorded may the adjudicator inspect it.
6. Record later effects and perform adversarial review of every shadow auto
   decision without changing Policy v0.

## Stop rules

- No real required gate: no M0, even if a local test says AUTO.
- Unknown delegation, effective privileges, or native controls: no valid M0.
- Human decision arrived before the receipt: discard as prospective evidence.
- Changed branch/commit after receipt: new proposal and new decision required.
- Severe false auto: supported verdict unavailable; preserve the failure.

At M1, compute real-gate reduction and authority exposure against the native
baseline. Keep conservative/balanced/permissive alternatives labeled as
post-experiment counterfactuals, never as a rerun of Policy v0.

## GitHub Native Controls & Ruleset Detail Limitations

The read-only recorder App queries GitHub repository rulesets via `gh api`. If the `gh` CLI executable is unavailable at process launch (`FileNotFoundError`), encounters a launch permission failure (`PermissionError`), times out (`subprocess.TimeoutExpired`), produces output that cannot be decoded as text (`UnicodeDecodeError` on undecodable stdout or stderr, including stderr on an unsuccessful read), or successfully decoded text whose JSON parsing raises `RecursionError` due to excessive nesting (or `json.JSONDecodeError`), the adapter treats it as an inaccessible API read, preserving the fail-closed `UNKNOWN` behavior for each required field and `known=false` for the snapshot. While
`includes_parents=true` permits discovery and detail retrieval of inherited rulesets
where token permissions allow, organization- or enterprise-level rulesets whose
scopes are inaccessible to the repository installation token will return `None`
(inaccessible/404/403). Repository, organization, and enterprise rulesets require complete,
structurally valid targeting conditions; specifically, enterprise rulesets require exactly one
organization selector paired with a supported repository selector (and ref_name for branch/tag targets),
while lacking unsupported selectors like repository_id. Property-selector conditions (`organization_property` and
`repository_property`) must use `include`/`exclude` arrays of condition objects with required `name` and
`property_values` fields, and repository property entries may optionally specify source `custom` or `system`.
Absent, omitted, or unsupported targeting semantics must fail closed. Furthermore, all encountered rules
(such as `pull_request` and `required_status_checks`) must specify complete effective gate parameters
and control-defining fields. Furthermore, `pull_request` rules apply only to branch rulesets (`target == "branch"`). Missing, malformed, inconsistent, inaccessible, or materially redacted
detail—as well as any unsupported rule or condition shapes—forces `rulesets` to `UNKNOWN` and
`native_controls.known` to `false`, ensuring fail-closed security. Ruleset bypass actors (`bypass_actors`) must be structurally valid according to the GitHub REST schema: documented actor types are `Integration`, `OrganizationAdmin`, `RepositoryRole`, `Team`, `DeployKey`, `User`, `EnterpriseOwner`, and `EnterpriseRole`; supported bypass modes are `always`, `pull_request`, and `exempt`. `actor_id` is required and must be a positive integer for `Integration`, `RepositoryRole`, `Team`, and `User`. While the GitHub REST schema lists `EnterpriseRole` without explicitly stating its ID rule, GitHub's GraphQL `RepositoryRulesetBypassActor` exposes `enterpriseRoleDatabaseId` as the enterprise role's identifying ID (see https://docs.github.com/en/graphql/reference/repos#repositoryrulesetbypassactor), making a required positive integer a defensible fail-closed inference. `actor_id` is ignored for `OrganizationAdmin` and `EnterpriseOwner` per REST, and must be null (`None`) for `DeployKey`. Furthermore, `pull_request` bypass mode applies only to branch rulesets (`target == "branch"`) and is prohibited for `DeployKey`. Any unknown, omitted, malformed, or unsupported bypass actor values force `rulesets` to `UNKNOWN` and `native_controls.known` to `false`. Furthermore, `EnterpriseOwner` and `EnterpriseRole` bypass actors are permitted only when ruleset detail and summary `source_type` is `Enterprise`; while GitHub's organization ruleset guides mention enterprise actors as possible bypass choices, this collector adopts a conservative `source_type` acceptance rule as the reviewed task contract requiring Enterprise source for enterprise actors, and any enterprise actors encountered under `Repository` or `Organization` ruleset source types fail closed through `rulesets` as `UNKNOWN` and `native_controls.known` as `false`. Similarly, repository metadata
fetched via `GET /repos/{owner}/{repo}` must be structurally complete and valid: `default_branch`
must be a non-empty string, `private` must be a boolean flag, and `permissions` must be a dictionary
containing core boolean effective permissions (`pull`, `push`, `admin`) along with optional boolean
`maintain` and `triage` permissions, failing closed on empty, partial, or malformed permission maps.
Absent, omitted, or malformed repository metadata fields must force `repository_metadata` to `UNKNOWN` and `native_controls.known` to `false`. Similarly, default workflow permissions fetched via `GET /repos/{owner}/{repo}/actions/permissions/workflow` must be structurally complete and valid: `default_workflow_permissions` must be a string set to either `"read"` or `"write"`, and `can_approve_pull_request_reviews` must be a boolean flag, failing closed on missing, omitted, malformed, or unsupported workflow permission fields (such as empty dictionaries or string-typed boolean fields) which force `workflow_permissions` to `UNKNOWN` and `native_controls.known` to `false`. Similarly, environments fetched via `GET /repos/{owner}/{repo}/environments` must be structurally valid: any environment reporting a `branch_policy` protection rule must specify effective `deployment_branch_policy` details (failing closed to `UNKNOWN` if omitted or `null`), while valid environments without a branch-policy rule may report `null` or complete deployment branch policies. Protection rules of type `wait_timer` must specify a valid integer timer within the inclusive `0` to `43200` minutes range, failing closed on malformed values or timers exceeding `43200` minutes. Protection rules of type `required_reviewers` must specify a valid list of one through six total users or teams, failing closed on empty lists, malformed entries, or lists exceeding six total reviewers. Similarly, branch protection fetched via `GET /repos/{owner}/{repo}/branches/{branch}/protection` must be structurally complete and valid: it must not be empty or malformed; effective required pull request review parameters (`required_approving_review_count` as an integer and associated boolean flags including `require_last_push_approval`), required status checks (`strict` boolean alongside valid `checks` or `contexts`; if both `checks` and `contexts` are present, their set of required check names must be consistent and matching, failing closed on contradiction), administrator enforcement (`enforce_admins`), nested authority-bearing control objects (`dismissal_restrictions` and `bypass_pull_request_allowances` inside `required_pull_request_reviews` when present must not be null and top-level push `restrictions` when present may be null or a valid object) must contain valid `users`, `teams`, and `apps` arrays with fully validated actor identity fields (`id` and `login` for users, `id` and `slug` for teams, and `id` and non-empty `slug` for apps, while absent optional nested sections and top-level `restrictions: null` remain valid), and related branch protection flags must be fully valid, failing closed on missing, malformed, unsupported, or incomplete control data which forces `branch_protection` to `UNKNOWN` and `native_controls.known` to `false`. App permissions must remain read-only and must not be expanded to bypass access boundaries. Furthermore, API snapshots capture point-in-time state rather than historical enforcement proof.

## Git Snapshot Changed-Path Limitations

Local git snapshots capture committed changed paths via `git diff --name-only -z` (NUL-delimited output) to guarantee lossless reporting of paths containing unusual characters such as tabs (`\t`) and newlines (`\n`), preventing quoting or escaping defects (such as `"review\tpolicy.txt"` being misinterpreted). The collector enforces worktree cleanliness, bounds each Git subprocess invocation with a finite deadline (raising `subprocess.TimeoutExpired` and aborting capture without emitting a partial snapshot on timeout), and checks for mid-capture mutations of the worktree or referenced commits/branches, raising a `ValueError` if any asynchronous changes occur during collection.

