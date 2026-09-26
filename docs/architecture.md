# Architecture

```text
real task -> coding agent -> branch/PR -> proposed merge or staging effect
                                      |
                         trusted read-only collectors
                                      |
                        immutable pre-gate input snapshot
                                      |
                        deterministic Policy v0 (shadow)
                                      |
                         input/decision/receipt hashes
                                      |
                         real human/native gate -> executor
```

The lab is a research harness, not an authorization server. The collector's
trustworthiness is an explicit deployment requirement. Its local JSON and
hashes preserve an audit trail but do not prove that input data came from
GitHub or CI. GitHub native-control snapshots must be tied to the exact
repository, branch, workflow version, and decision time. Unknown fields force
human review. The effect scope in an `AUTO_AUTHORIZE` decision is pinned to a
resource, branch, and commit; changing that commit requires a new proposal.

Agent code is never given a merge/deploy credential by the lab. The shadow
runner has no effect-execution code. A future trusted executor would use
existing IAM/OIDC/CI after an actual authorization decision; 001B-T never
activates that route.

The lab itself is reusable across repositories, but Policy v0 is intentionally
narrow. It has no DSL, identity provider, secret store, dashboard, or tenant
model. Repository-specific path and CI facts belong in the frozen task and
evidence records, not hard-coded into a general platform.
