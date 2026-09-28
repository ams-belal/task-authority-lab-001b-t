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

The read-only recorder App queries GitHub repository rulesets via `gh api`. While
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
and control-defining fields. Missing, malformed, inconsistent, inaccessible, or materially redacted
detail—as well as any unsupported rule or condition shapes—forces `rulesets` to `UNKNOWN` and
`native_controls.known` to `false`, ensuring fail-closed security. Similarly, repository metadata
fetched via `GET /repos/{owner}/{repo}` must be structurally complete and valid: `default_branch`
must be a non-empty string, `private` must be a boolean flag, and `permissions` must be a dictionary
containing core boolean effective permissions (`pull`, `push`, `admin`) along with optional boolean
`maintain` and `triage` permissions, failing closed on empty, partial, or malformed permission maps.
Absent, omitted, or malformed repository metadata fields must force `repository_metadata` to `UNKNOWN` and `native_controls.known` to `false`. Similarly, default workflow permissions fetched via `GET /repos/{owner}/{repo}/actions/permissions/workflow` must be structurally complete and valid: `default_workflow_permissions` must be a string set to either `"read"` or `"write"`, and `can_approve_pull_request_reviews` must be a boolean flag, failing closed on missing, omitted, malformed, or unsupported workflow permission fields (such as empty dictionaries or string-typed boolean fields) which force `workflow_permissions` to `UNKNOWN` and `native_controls.known` to `false`. Similarly, branch protection fetched via `GET /repos/{owner}/{repo}/branches/{branch}/protection` must be structurally complete and valid: it must not be empty or malformed; effective required pull request review parameters (`required_approving_review_count` as an integer and associated boolean flags), required status checks (`strict` boolean alongside valid `checks` or `contexts`), administrator enforcement (`enforce_admins`), and related branch protection flags must be fully valid, failing closed on missing, malformed, unsupported, or incomplete control data which forces `branch_protection` to `UNKNOWN` and `native_controls.known` to `false`. App permissions must remain read-only and must not be expanded to bypass access boundaries. Furthermore, API snapshots capture point-in-time state rather than historical enforcement proof.
