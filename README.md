# Task Authority Lab

A small, shadow-only research harness for prospective Task Authority Decisions.
It records a proposed consequential effect, evaluates a deterministic Policy v0,
and freezes a receipt before the real human gate resolves. The lab has no merge,
deploy, IAM, or credential-issuing function.

## Local check

```sh
python3 -m unittest discover -s tests -v
```

## Repository workflow

`main` is the protected branch. `Lab tests / lab-tests` is the required status
check. The `Bot proposal` workflow can create one of two branches and pull
requests using the repository's built-in `GITHUB_TOKEN`:

- `setup-gate-probe` adds only a harmless documentation file for environment
  verification. It is not an experiment task.
- `task-0001` applies the reviewed `proposals/task-0001.patch` to fix the Git
  evidence collector's dirty-worktree defect. The patch is source material for
  the bot proposal, not code already merged into `main`.

The bot workflow has only the repository content and pull-request permissions
needed to propose these changes. It never approves or merges a pull request.
The lab's shadow decisions also never approve or merge a pull request. A human
reviewer and GitHub's branch protection remain authoritative.

See [architecture](docs/architecture.md), [threat model](docs/threat_model.md),
[instrumentation](docs/instrumentation.md), and [runbook](docs/experiment_runbook.md).
