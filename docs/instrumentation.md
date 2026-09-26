# Instrumentation specification

## Required records

1. **Task:** ID, text, source, initiating principal, creation time, allowed and
   prohibited paths/effects, branch, workflow version, expiry.
2. **Agent event:** task ID, agent identity, time, action, target, parameters,
   result, artifact reference. Distinguish agent from the account/token used by
   a trusted executor.
3. **Effect proposal:** exact resource/action/commit/branch/time and expected
   downstream triggers.
4. **Evidence graph:** one item per checkable fact, with source, exact value,
   observation time, pre-effect availability, artifact reference, integrity
   hash, deterministic/probabilistic kind, evaluator identity/version/confidence
   where relevant. Agent prose does not become a passing check.
5. **Native controls:** branch protection, rulesets, CODEOWNERS, required
   reviews, workflow permissions, environment reviewers, OIDC/IAM conditions,
   credential holder/type/scope/lifetime, and effective snapshot time.
6. **Human gate:** active rule and version, gate request time, approver, human
   outcome and time, rationale/repair, and evidence that it was required.
7. **Outcome:** merge/staging result, later CI, repairs, rollback, security or
   privilege finding, and downstream effects. Kept out of Pass 1.

Only metadata about credentials may be recorded. Never inspect, print, hash,
serialize, or store secret values. Every time-sensitive observation must be
bound to a UTC timestamp and commit. A current ruleset is not evidence of its
historical state. If an API response is unavailable or ambiguous, record
`UNKNOWN`, not `false`.

## Current collectors

`git-snapshot` reads local branch, HEAD, base commit, changed paths, and clean
state. `github-snapshot` reads branch protection, rulesets, Actions workflow
permissions, and repository metadata through the user's `gh` authentication.
Its `known` value is false if any call fails. CODEOWNERS, protected environments,
OIDC/IAM, and effective agent-token scope still need an environment-specific
adapter before M0 can be called valid. This explicit gap prevents a test
fixture or partial API snapshot from masquerading as a complete authority
record.

## Context acquisition cost log

Record start time, engineer/operator time, number of integrations, manual
configuration steps, automatic evidence coverage, missing evidence, decision
runtime, workflow changes, and first valid receipt time. Until M0, report
`TIME_TO_FIRST_VALID_TAD = NOT_REACHED` and integration complexity as
unclassified, not LOW by assumption.
