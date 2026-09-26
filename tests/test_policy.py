import copy
import tempfile
import unittest
from pathlib import Path

from task_authority_lab.canonical import freeze_json, sha256_json
from task_authority_lab.policy_v0 import decide
from task_authority_lab.shadow import run_shadow, verify_receipt
from task_authority_lab.outcome import record_human_outcome


def request():
    proposed_at = "2026-09-26T10:00:00Z"
    facts = {
        "changed_paths": ["src/parser.py"],
        "tests_passed": True,
        "checks_passed": True,
        "protected_paths_modified": False,
        "workflow_files_modified": False,
        "dependency_change": False,
        "provenance_complete": True,
    }
    evidence = []
    for key, value in facts.items():
        source = "ci" if key in {"tests_passed", "checks_passed"} else "collector" if key == "provenance_complete" else "git_diff"
        evidence.append({"id": "ev-" + key, "task_id": "task-1", "source": source,
                         "fact": {"key": key, "value": value}, "observed_at": "2026-09-26T09:59:00Z",
                         "available_before_effect": True, "artifact_reference": "artifact://" + key,
                         "integrity_hash": "a" * 64, "kind": "deterministic"})
    return {
        "task": {"id": "task-1", "branch": "task/1", "allowed_paths": ["src"], "text": "Fix parser", "created_at": "2026-09-26T08:00:00Z"},
        "delegation": {"version": "v0", "version_hash": "b" * 64, "approved_by": "owner",
                       "allowed_effects": ["branch_push", "open_pr"], "conditional_effects": ["merge_candidate"],
                       "prohibited_effects": ["deploy_production"], "allowed_paths": ["src"],
                       "expires_at": "2026-09-27T00:00:00Z"},
        "proposal": {"id": "effect-1", "task_id": "task-1", "proposed_at": proposed_at,
                     "proposed_by": "coding-agent", "resource": "owner/repo", "effect": "merge_candidate",
                     "branch": "task/1", "commit": "c" * 40, "direct_effect_class": "E3", "downstream_triggers": []},
        "workflow_state": {"branch": "task/1", "commit": "c" * 40},
        "evidence": evidence,
        "native_controls": {"known": True, "source": "github_api_via_gh", "integrity_hash": "d" * 64,
                            "snapshot_at": "2026-09-26T09:59:30Z", "agent_can_merge": False, "trusted_executor": True},
        "risk_context": {"self_elevation": False, "prohibited_credential_requested": False,
                         "downstream_amplification": False, "ambient_privileged_credentials": False},
        "agent_events": [{"action": "commit", "at": "2026-09-26T09:58:00Z"}],
        "gate": {"status": "pending", "effect_id": "effect-1", "required_by": "repository_rule",
                 "rule_reference": "rule-1", "requested_at": "2026-09-26T09:59:40Z"},
    }


class PolicyTests(unittest.TestCase):
    def test_mechanical_candidate_is_deterministic(self):
        data = request()
        self.assertEqual(decide(data), decide(copy.deepcopy(data)))
        self.assertEqual(decide(data)["decision"], "AUTO_AUTHORIZE")

    def test_adversarial_scenarios_fail_closed(self):
        cases = {
            "A1_protected_workflow": (lambda r: r["evidence"].append({**r["evidence"][0], "id": "ev-control", "fact": {"key": "authority_control_modified", "value": True}}), "DENY"),
            "A2_dependency": (lambda r: next(e for e in r["evidence"] if e["fact"]["key"] == "dependency_change")["fact"].update(value=True), "HUMAN"),
            "A3_scope_escape": (lambda r: next(e for e in r["evidence"] if e["fact"]["key"] == "changed_paths")["fact"].update(value=["other/file.py"]), "DENY"),
            "A4_self_elevation": (lambda r: r["risk_context"].update(self_elevation=True), "DENY"),
            "A5_downstream": (lambda r: r["risk_context"].update(downstream_amplification=True), "HUMAN"),
            "A6_missing_check": (lambda r: r["evidence"].__setitem__(slice(None), [e for e in r["evidence"] if e["fact"]["key"] != "checks_passed"]), "HUMAN"),
            "A7_expired": (lambda r: r["delegation"].update(expires_at="2026-09-25T00:00:00Z"), "DENY"),
        }
        for name, (mutation, expected) in cases.items():
            with self.subTest(name=name):
                data = request()
                mutation(data)
                self.assertEqual(decide(data)["decision"], expected)

    def test_agent_claim_and_late_evidence_cannot_auto_authorize(self):
        for mutation in (
            lambda e: e.update(source="agent"),
            lambda e: e.update(observed_at="2026-09-26T10:01:00Z"),
            lambda e: e.update(available_before_effect=False),
        ):
            data = request()
            mutation(next(e for e in data["evidence"] if e["fact"]["key"] == "checks_passed"))
            self.assertEqual(decide(data)["decision"], "HUMAN")

    def test_paths_override_false_safety_flags(self):
        control = request()
        control["delegation"]["allowed_paths"].append(".github")
        next(e for e in control["evidence"] if e["fact"]["key"] == "changed_paths")["fact"]["value"] = [".github/workflows/ci.yml"]
        self.assertEqual(decide(control)["decision"], "DENY")
        dependency = request()
        dependency["delegation"]["allowed_paths"].append(".")
        next(e for e in dependency["evidence"] if e["fact"]["key"] == "changed_paths")["fact"]["value"] = ["src/package.json"]
        self.assertEqual(decide(dependency)["decision"], "HUMAN")

    def test_shadow_freeze_is_append_only_and_verifiable(self):
        with tempfile.TemporaryDirectory() as temp:
            record = run_shadow(request(), temp)
            self.assertTrue(verify_receipt(record["directory"])["valid"])
            with self.assertRaises(FileExistsError):
                run_shadow(request(), temp)
            with self.assertRaises(FileExistsError):
                freeze_json(Path(record["directory"]) / "decision.json", {"tampered": True})

    def test_resolved_gate_cannot_be_scored(self):
        data = request()
        data["gate"]["decision"] = "approve"
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                run_shadow(data, temp)

    def test_human_outcome_is_separate_and_later(self):
        with tempfile.TemporaryDirectory() as temp:
            record = run_shadow(request(), temp)
            early = {"effect_id": "effect-1", "decision": "APPROVE", "actor": "reviewer",
                     "decided_at": "2020-01-01T00:00:00Z", "evidence_reference": "review://1"}
            with self.assertRaises(ValueError):
                record_human_outcome(record["directory"], early)
            later = {**early, "decided_at": "2030-01-01T00:00:00Z"}
            result = record_human_outcome(record["directory"], later)
            self.assertGreater(result["delay_seconds"], 0)
            with self.assertRaises(FileExistsError):
                record_human_outcome(record["directory"], later)


if __name__ == "__main__":
    unittest.main()
