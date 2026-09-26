# Threat model

| Threat | Policy or measurement response | Residual limitation |
|---|---|---|
| Agent changes files outside task scope | `DENY` on trusted changed-path evidence | Collector must be separate from agent. |
| Agent changes control files | `DENY` on control path or explicit self-elevation | New authority-control paths need catalog updates. |
| Agent adds dependency or lifecycle hook | `HUMAN` on dependency files or evidence flag | Indirect imports and vendored code need adversarial review. |
| Agent alters code that later runs with privileged CI | `HUMAN` when downstream amplification is not disproved | Trigger graph and credential scope must be verified. |
| Agent forges test results | Agent-sourced claims are ignored for auto decisions | CI origin still needs authentication. |
| Agent supplies a late evaluator result | Evidence observed after proposal is ignored | Clock/source integrity still matters. |
| Agent acts through maintainer identity | Record agent, token holder, reviewer, and executor separately | Account attribution may be incomplete. |
| Repo changes after decision | Commit-pinned scope; any new commit needs a new decision | No executor exists in 001B-T to enforce this in practice. |
| Agent or operator tampers with frozen files | Exclusive writes and SHA-256 replay detect changes | Local single-user filesystem is not tamper-proof. |
| Shadow result biases human baseline | Keep result hidden until human acts | Needs operational discipline in live workflow. |

**Severe false authorization:** any `AUTO_AUTHORIZE` that would expose a
privileged credential, modify a protected control, self-approve, persist beyond
delegation, or amplify into materially stronger downstream authority prevents
`PRODUCT_HYPOTHESIS_SUPPORTED`. Every live auto result requires a separate
malicious-agent counterfactual. Passing the fixture tests is not evidence of
live safety.
