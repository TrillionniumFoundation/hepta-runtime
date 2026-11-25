#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Replay exact native snapshot capacity wires, inputs and canonical exports.

No producer verdict authorizes a pass. The fixed request sequences are replayed
against digest-bound original frames; every response/export must be consumed.
This proves three finite capacity observations, not active encoding cancellation.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import rea_build_evidence as build
import rea_elf_evidence_family_evidence as replay
import rea_elf_evidence_family_qualification as family
import rea_elf_format_evidence as formats
import rea_operation_evidence as operation
import rea_operation_qualification as q
import rea_readback_capacity_qualification as capacity
from rea_full_qualification import Selection


class CapacityReplay(replay.ReplaySession):
    def export(self, name, path, expected=None, expected_raw=None):
        response = self.call(name, "export_evidence_bundle", {"path": str(path), "overwrite": True})
        saved = self.state["exports"][name]
        raw = replay.read_gzip(self.root, saved["artifact"], capacity.MAX_EXPORT_BYTES)
        q.require(saved["file"] == {"path": str(path), "bytes": len(raw), "sha256": replay.sha(raw)},
                  "export file identity differs from retained original bytes")
        bundle = family.validate_bundle(capacity.parse_export(raw), expected)
        q.require(family.payload(response, target=False)["result"] == {
            "path": str(path), "bytes": len(raw), "records": len(bundle["records"]), "unknowns": 0},
            "export wire receipt differs from complete canonical bytes")
        q.require(raw == family.canonical_json(bundle) and (expected_raw is None or raw == expected_raw),
                  "canonical export is incomplete or changed")
        self.exports[name] = raw
        return raw, bundle


def validate_input(root, name, expected, after):
    """Read the retained original only; never repair or regenerate it in place."""
    observed = build.read_regular(root, "workspace/" + name + ".elf", expected["bytes"])
    size = 20 if name == "small" else capacity.DESCRIPTORS[name]
    descriptor = (bytes(range(256)) * ((size + 255) // 256))[:size]
    expected_bytes = q.elf(q.note(descriptor=descriptor)) + (bytes(size) if name != "small" else b"")
    identity = {key: expected[key] for key in ("path", "bytes", "sha256")}
    q.require(len(observed) == expected["bytes"] and replay.sha(observed) == expected["sha256"]
              and observed == expected_bytes and after == identity, "actual capacity fixture differs: " + name)


def validate_report(repo, path, expected_sha256):
    repo, path = Path(repo), Path(path)
    q.require(repo.is_absolute() and path.is_absolute(), "explicit absolute paths are required")
    root = path.parent
    raw = build.read_regular(root, path.name, q.MAX_WIRE_BYTES)
    q.require(hashlib.sha256(raw).hexdigest() == expected_sha256, "capacity receipt digest differs")
    report = q.parse_json(raw)
    q.require(report["schema"] == capacity.SCHEMA and report["profile"] == capacity.PROFILE,
              "unreviewed native capacity profile")
    q.require(report["errors"] == [] and report["producer_exit_code"] == 0,
              "capacity execution was incomplete or recorded an error")
    source = operation.artifact_json(root, report["source_before"])
    q.require(source == operation.artifact_json(root, report["source_after"])
              and source == Selection(repo, root / "unused-target", root).snapshot(),
              "capacity source combination changed")
    q.require(operation.artifact_json(root, report["source_events"]) == {
        "event_count": 0, "retained_events": [], "events_truncated": False, "errors": []},
        "source monitoring changed or lost coverage")
    q.require(report["producer_before"] == report["producer_after"]
              and [item["path"] for item in report["producer_before"]] == list(capacity.FILES),
              "capacity producer/consumer input inventory differs")
    for item in report["producer_before"]:
        operation.read_artifact(repo, item)
    binary = formats.observed_identity(report["binary_before"])
    q.require(binary == report["binary_after"], "selected native binary changed")
    binding = None
    if report.get("build_evidence") is not None:
        binding = build.validate_bundle(root, report["build_evidence"], source, binary)
    workspace = root / "workspace"
    inputs = capacity.fixtures(workspace, write=False)
    q.require(operation.artifact_json(root, report["fixtures"]) == inputs, "regenerated input manifest differs")
    for name, item in inputs.items():
        validate_input(root, name, item, report["fixtures_after"][name])
    q.require(operation.artifact_json(root, report["config"]) == formats.producer.config_for(root),
              "native filesystem permission profile differs")
    q.require(set(report["sessions"]) == {"native/" + name for name in capacity.SCENARIOS},
              "capacity owner set differs")
    results, owners, call_counts = {}, set(), {}
    for scenario in capacity.SCENARIOS:
        session = CapacityReplay(root, "native", scenario, report["sessions"]["native/" + scenario], report, workspace)
        owner = tuple(sorted(session.launch["owner"].items()))
        q.require(owner not in owners, "capacity cases reused an owner")
        owners.add(owner)
        results[scenario] = capacity.EXERCISES[scenario](session, inputs, workspace)
        session.finish()
        call_counts[scenario] = len(session.rows)
    return {"schema": "hepta.rea.readback-capacity-assessment.v1", "profile": capacity.PROFILE,
            "finite_status": "PASS", "qualified": False, "results": results, "call_counts": call_counts,
            "normal_owner_closes": len(owners), "receipt_sha256": expected_sha256,
            "source_tree_sha256": source["tree_sha256"], "native_binary_sha256": binary["sha256"],
            "build_source_binding": binding, "active_encoding_cancellation": "NOT_OBSERVED",
            "scope": "count, total-byte and per-snapshot limits; retained cursors/evidence and release recovery"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    result = validate_report(args.repo, args.report, args.sha256)
    print(q.json_bytes(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
