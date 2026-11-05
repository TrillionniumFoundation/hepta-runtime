#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze native execution identities after local qualification and before replay."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def create(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--requests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    qualification_bytes = args.qualification.read_bytes()
    qualification = json.loads(qualification_bytes)
    assert qualification["passed"] and qualification["completed"] and qualification["source_unchanged_after_format"]
    assert qualification["protocol_sha256"] == sha((here / "LOCAL_PROTOCOL.json").read_bytes())
    assert len(qualification["commands"]) == 6
    assert all(row["exit_code"] == 0 and not row["timed_out"] for row in qualification["commands"])
    sources = qualification["source_after_last_command"]
    assert sources == qualification["source_after_format"] and len(sources) == 14
    source_bytes = (json.dumps(sources, indent=2) + "\n").encode()
    module_sha = {row["path"]: row["sha256"] for row in sources}["src/mcp/weight_bellman.rs"]
    handoff_bytes = (args.requests / "REQUEST_HANDOFF.json").read_bytes()
    assert sha(handoff_bytes) == "a895f3045db4b2e5d124f67448602782a1aa189904d04f5a1d02ef9fb68d6792"
    handoff = json.loads(handoff_bytes)
    for relative, identity in handoff["group_files"].items():
        data = (args.requests / Path(relative).name).read_bytes()
        assert len(data) == identity["bytes"] and sha(data) == identity["sha256"]
    scripts = {"driver": "run_native_corpus.py", "supervisor": "supervise_native_corpus.py",
               "bridge_io": "bridge_io.py", "mcp_fixture_client": "mcp_fixture_client.py",
               "source_health": "verify_source_health.py"}
    protocol = {
        "schema": "hepta.native-bellman-execution-protocol.v1",
        "frozen_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "declared_public_parent_commit": "e7a2688acc5504412d45160a08d2bf864be6b650",
        "observed_qualification_checkout_head": qualification["checkout_head"],
        "observed_qualification_checkout_tree": qualification["base_tree"],
        "checkout_scope": "Recorded checkout identity may precede the public parent; explicit source overlays are bound by the complete qualified source manifest.",
        "binary_sha256": qualification["binary"]["sha256"],
        "binary_bytes": qualification["binary"]["bytes"],
        "bellman_module_sha256": module_sha,
        "qualified_source_manifest_sha256": sha(source_bytes),
        "local_qualification_sha256": sha(qualification_bytes),
        "cargo_lock_sha256": qualification["cargo_lock_sha256"],
        "rustc_version": qualification["rustc_version"],
        "script_sha256": {name: sha((here / filename).read_bytes()) for name, filename in scripts.items()},
        "preparer_sha256": sha(Path(__file__).read_bytes()),
        "request_handoff_sha256": sha(handoff_bytes),
        "independent_acceptance_protocol_sha256": handoff["protocol_sha256"],
        "expected_groups": sorted(Path(name).name for name in handoff["group_files"]),
        "planned_worlds": 320, "planned_nodes": 246160, "planned_branches": 277892,
        "request_order": "lexicographically sorted group names and original JSONL row order",
        "native_tool": "weight_bellman_plan",
        "input_scope": "Only request_id/method/params.states; no reference Q, actions, truth or scientific policy lookup enters the native driver.",
        "resource_caps": {"driver_cpu_seconds": 90, "child_cpu_seconds": 210,
            "execution_wall_seconds": 600, "outer_wall_seconds": 660,
            "address_space_bytes_per_process": 8589934592, "nofile_per_process": 1024},
        "termination_grace": "After the outer timeout, TERM then KILL with at most 10 seconds wait each; any timeout is a failed execution.",
        "failure_accounting": "Every attempted RPC retains its full response or error. Unattempted worlds remain missing against the original 320 denominator. Hard CPU termination may leave only flushed partial rows and outer termination evidence; never fabricate complete internal receipts.",
        "measurement": "Use outer spawn-to-exit wall and cumulative waited-descendant CPU for full driver cost; report internal timers separately, never add overlapping intervals. Explicitly identify supervisor setup/outer receipt publication outside that measured interval.",
        "independent_Q_gate": "absolute error <= 2e-12 * (1 + abs(reference_Q)); exact legal masks and first-maximum actions; unchanged from the frozen export protocol",
        "near_ties": "Report discrepancies without changing the predeclared gates or action ordering.",
        "frozen_journal_contract_driver_sha256": "f725928b2c5dd9aeb53166907ec277f17f6ad7f30f63ad322fb978fd1b40fb26",
        "frozen_journal_contract_protocol_sha256": "f06634e9e73182c149d8a94bd5771648f39ce0516c79dbfa64332a7376c7bd76",
        "journal_contract_scope": "Separate regression phase using the same qualified binary; not part of the 320 Bellman requests or this phase's timing.",
        "source_health": "Require unchanged executed binary and driver/helpers and compare all 14 qualified Rust identities and the built binary again after every qualification phase.",
        "model_efficacy_scope": "Engineering replay of already-exposed finite worlds, with a separate independent verification/J replay. No new scientific holdout, true-law authentication, checkpoint edit or production promotion.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=False)
    create(args.output.parent / "QUALIFIED_SOURCE_MANIFEST.json", source_bytes)
    create(args.output.parent / "LOCAL_QUALIFICATION.json", qualification_bytes)
    encoded = (json.dumps(protocol, indent=2, allow_nan=False) + "\n").encode()
    create(args.output, encoded)
    print(json.dumps({"protocol_sha256": sha(encoded), "source_manifest_sha256": sha(source_bytes),
        "local_qualification_sha256": sha(qualification_bytes), "binary_sha256": protocol["binary_sha256"]}))


if __name__ == "__main__":
    main()
