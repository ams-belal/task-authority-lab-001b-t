"""Local CLI for read-only collection and shadow-only decisions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .canonical import freeze_bytes, sha256_file
from .collector.git import snapshot as git_snapshot
from .collector.github import snapshot as github_snapshot
from .collector.events import record_event
from .outcome import record_human_outcome
from .shadow import run_shadow, verify_receipt


def main() -> None:
    parser = argparse.ArgumentParser(prog="tad-lab")
    commands = parser.add_subparsers(dest="command", required=True)
    p_git = commands.add_parser("git-snapshot", help="Read branch and diff facts")
    p_git.add_argument("repository")
    p_git.add_argument("base_ref")
    p_native = commands.add_parser("github-snapshot", help="Read native GitHub controls via gh")
    p_native.add_argument("repository", help="owner/name")
    p_native.add_argument("base_branch")
    p_shadow = commands.add_parser("shadow", help="Freeze a shadow decision")
    p_shadow.add_argument("request_json")
    p_shadow.add_argument("decisions_directory")
    p_verify = commands.add_parser("verify", help="Verify a frozen receipt")
    p_verify.add_argument("decision_directory")
    p_hash = commands.add_parser("hash", help="SHA-256 of a local file")
    p_hash.add_argument("path")
    p_freeze = commands.add_parser("freeze", help="Create a no-overwrite frozen copy")
    p_freeze.add_argument("source")
    p_freeze.add_argument("destination")
    p_event = commands.add_parser("record-event", help="Freeze an event envelope")
    p_event.add_argument("event_json")
    p_event.add_argument("events_directory")
    p_outcome = commands.add_parser("human-outcome", help="Freeze a post-decision gate result")
    p_outcome.add_argument("decision_directory")
    p_outcome.add_argument("outcome_json")
    args = parser.parse_args()

    if args.command == "git-snapshot":
        result = git_snapshot(args.repository, args.base_ref)
    elif args.command == "github-snapshot":
        result = github_snapshot(args.repository, args.base_branch)
    elif args.command == "shadow":
        request = json.loads(Path(args.request_json).read_text(encoding="utf-8"))
        result = run_shadow(request, args.decisions_directory)
    elif args.command == "verify":
        result = verify_receipt(args.decision_directory)
    elif args.command == "hash":
        result = {"sha256": sha256_file(args.path)}
    elif args.command == "freeze":
        result = {"sha256": freeze_bytes(args.destination, Path(args.source).read_bytes()), "destination": args.destination}
    elif args.command == "record-event":
        result = record_event(json.loads(Path(args.event_json).read_text(encoding="utf-8")), args.events_directory)
    elif args.command == "human-outcome":
        result = record_human_outcome(args.decision_directory, json.loads(Path(args.outcome_json).read_text(encoding="utf-8")))
    else:
        raise AssertionError(args.command)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
