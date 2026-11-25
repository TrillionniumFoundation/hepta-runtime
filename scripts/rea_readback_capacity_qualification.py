#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Observe native snapshot limits through the shipping MCP, preserving all wires.

These three finite sequences use actual ELF observations and canonical exports.
No limit is changed, no private registry is injected, and no upstream readback
equivalence is claimed. Active cancellation remains a separate observation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import rea_elf_evidence_family_qualification as family
import rea_elf_format_qualification as formats
import rea_operation_qualification as q
from rea_full_qualification import Selection, SourceMonitor


SCHEMA = "hepta.rea.readback-capacity.v1"
PROFILE = "hepta.evidence-bundle-readback/linux-capacity/v1"
SCENARIOS = ("extension-count", "extension-total-bytes", "extension-single-bytes")
MAX_EXPORT_BYTES = 96 * 1024 * 1024
LIMITS = {"max_snapshot_bytes": 64 * 1024 * 1024,
          "max_retained_bytes": 128 * 1024 * 1024, "max_snapshots": 4}
DESCRIPTORS = {"aggregate": 25 * 1024 * 1024, "single": 33 * 1024 * 1024}
FILES = ("scripts/rea_readback_capacity_qualification.py",
         "scripts/rea_readback_capacity_evidence.py", "tests/rea_readback_capacity_tests.py")


def parse_export(raw):
    """Bound a complete disk export independently of the unchanged MCP allowance."""
    q.require(len(raw) <= MAX_EXPORT_BYTES, "complete export exceeds its fixed disk allowance")
    def members(items):
        value = {}
        for key, item in items:
            q.require(key not in value, "duplicate export JSON member: " + key)
            value[key] = item
        return value
    def number(token):
        value = float(token)
        q.require(math.isfinite(value), "non-finite export JSON number")
        return value
    return json.loads(raw, object_pairs_hook=members, parse_float=number,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          q.QualificationError("non-finite export JSON constant")))


def fixtures(workspace, write=False):
    result = {}
    for name, size in (("small", 20), *DESCRIPTORS.items()):
        descriptor = (bytes(range(256)) * ((size + 255) // 256))[:size]
        raw = q.elf(q.note(descriptor=descriptor)) + (bytes(size) if name != "small" else b"")
        path = workspace / (name + ".elf")
        if write:
            family.write_new(path, raw)
        result[name] = {"path": str(path), "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(), "descriptor_bytes": size,
                        "descriptor_sha256": hashlib.sha256(descriptor).hexdigest()}
    return result


def cache_refusal(response, reason):
    error = family.public_error(response)
    q.require(error["code"] == "resource_constraint" and error["category"] == "resource_constraint"
              and error["retryable"] is False and error["details"] == {
                  "operation": "read_evidence_bundle", "resource": "evidence-snapshot-cache",
                  "reason": reason, "reported_limits": LIMITS}, "snapshot refusal changed its actual limit/reason")


def add_small(session, fixture, number):
    arguments = {"path": fixture["path"], "max_entries": 32 - number}
    record = q.evidence_value(session.call("observation-" + str(number), "inspect_elf_notes", arguments))
    facts = {key: fixture[key] for key in ("path", "bytes", "sha256")}
    q.check_independent_facts(record, {"arguments": arguments, "facts": {
        **facts, "entries": 1, "tables": 1, "format": "elf64", "byte_order": "little",
        "owner": "GNU", "descriptor_hex": bytes(range(20)).hex()}})
    return record


def freeze(session, name, raw, records):
    return family.readback_page(session.call(name, "read_evidence_bundle", {"length": 17}),
                                raw, records, 0, 17)["snapshot_id"]


def replay_edges(session, name, snapshot_id, raw, records):
    for suffix, offset in (("start", 0), ("middle", len(raw) // 2), ("end", max(0, len(raw) - 17))):
        family.readback_page(session.call(name + "-" + suffix, "read_evidence_bundle",
            {"snapshot_id": snapshot_id, "offset": offset, "length": 17}),
            raw, records, offset, 17, snapshot_id)


def release(session, name, snapshot_id, snapshots):
    raw = snapshots.pop(snapshot_id)
    family.snapshot_release(session.call(name, "close_evidence_snapshot", {"snapshot_id": snapshot_id}),
        snapshot_id, True, len(raw), len(snapshots), sum(map(len, snapshots.values())))


def exercise_count(session, inputs, workspace):
    records, snapshots = [], {}
    family.complete(session.call("empty", "get_evidence_bundle", {}), [])
    for number in range(5):
        records.append(add_small(session, inputs["small"], number))
        raw, _ = session.export("export-" + str(number), workspace / "count.json", records)
        if number < 4:
            snapshot_id = freeze(session, "freeze-" + str(number), raw, len(records))
            q.require(snapshot_id not in snapshots, "distinct observations reused a snapshot")
            snapshots[snapshot_id] = raw
            if number == 0:
                q.require(freeze(session, "deduplicate", raw, 1) == snapshot_id,
                          "identical snapshot was not deduplicated")
        else:
            cache_refusal(session.call("count-full", "read_evidence_bundle", {"length": 17}),
                          "The retained snapshot count limit was reached.")
    first_id, first_raw = next(iter(snapshots.items()))
    replay_edges(session, "old-after-count-failure", first_id, first_raw, 1)
    session.export("count-failure-keeps-evidence", workspace / "count.json", records, raw)
    release(session, "release-one", first_id, snapshots)
    replacement = freeze(session, "recover-after-release", raw, len(records))
    snapshots[replacement] = raw
    q.require(len(snapshots) == 4, "released capacity was not reusable")
    for number, snapshot_id in enumerate(tuple(snapshots)):
        release(session, "release-rest-" + str(number), snapshot_id, snapshots)
    session.export("release-keeps-evidence", workspace / "count.json", records, raw)
    return {"distinct_live_snapshots": 4, "count_refusals": 1, "restored_zero": True}


def observe_large(session, fixture, workspace):
    arguments = {"path": fixture["path"], "max_file_bytes": 128 * 1024 * 1024}
    limits = family.overflow(session.call("large-observation", "inspect_elf_notes", arguments), "inspect_elf_notes")
    raw, bundle = session.export("large-export", workspace / "large.json", None)
    q.require(len(bundle["records"]) == 1, "large observation did not retain exactly one record")
    record = bundle["records"][0]
    q.require(record["evidence_id"] == limits["evidence_id"], "overflow reference did not name the exported record")
    facts = {key: fixture[key] for key in ("path", "bytes", "sha256")}
    q.check_independent_facts(record, {"arguments": arguments, "facts": {
        **facts, "entries": 1, "tables": 1, "format": "elf64", "byte_order": "little",
        "owner": "GNU", "descriptor_hex": None}})
    entry = record["normalized_result"]["entries"][0]
    text = entry["gnu"]["build_id_hex"]
    q.require(entry["descsz"] == fixture["descriptor_bytes"]
              and entry["descriptor"]["sha256"] == fixture["descriptor_sha256"]
              and len(text) == 2 * fixture["descriptor_bytes"]
              and hashlib.sha256(bytes.fromhex(text)).hexdigest() == fixture["descriptor_sha256"],
              "large export changed or omitted the independent descriptor")
    return raw, bundle["records"]


def exercise_total(session, inputs, workspace):
    family.complete(session.call("empty", "get_evidence_bundle", {}), [])
    raw, records = observe_large(session, inputs["aggregate"], workspace)
    q.require(LIMITS["max_retained_bytes"] // 3 < len(raw) < LIMITS["max_retained_bytes"] // 2,
              "fixture does not separate total bytes from the count/per-snapshot limits")
    snapshots = {freeze(session, "freeze-large", raw, 1): raw}
    first_id = next(iter(snapshots))
    records.append(add_small(session, inputs["small"], 0))
    second, _ = session.export("second-export", workspace / "large.json", records)
    snapshots[freeze(session, "freeze-second", second, 2)] = second
    q.require(len(snapshots) == 2 and sum(map(len, snapshots.values())) < LIMITS["max_retained_bytes"],
              "first two complete snapshots do not fit the stated aggregate budget")
    records.append(add_small(session, inputs["small"], 1))
    current, _ = session.export("third-export", workspace / "large.json", records)
    q.require(len(current) < LIMITS["max_snapshot_bytes"]
              and len(current) + sum(map(len, snapshots.values())) > LIMITS["max_retained_bytes"],
              "third snapshot does not independently exceed only the aggregate limit")
    cache_refusal(session.call("total-bytes-full", "read_evidence_bundle", {"length": 17}),
                  "Canonical bundle exceeds the available snapshot byte budget.")
    replay_edges(session, "old-after-byte-failure", first_id, raw, 1)
    session.export("byte-failure-keeps-evidence", workspace / "large.json", records, current)
    release(session, "release-large", first_id, snapshots)
    snapshots[freeze(session, "recover-total-after-release", current, 3)] = current
    for number, snapshot_id in enumerate(tuple(snapshots)):
        release(session, "release-rest-" + str(number), snapshot_id, snapshots)
    session.export("release-keeps-evidence", workspace / "large.json", records, current)
    return {"retained_before_refusal": 2, "aggregate_refusals": 1, "restored_zero": True}


def exercise_single(session, inputs, workspace):
    family.complete(session.call("empty", "get_evidence_bundle", {}), [])
    empty, _ = session.export("export-empty", workspace / "large.json", [])
    empty_id = freeze(session, "freeze-empty", empty, 0)
    raw, records = observe_large(session, inputs["single"], workspace)
    q.require(LIMITS["max_snapshot_bytes"] < len(raw) < LIMITS["max_retained_bytes"] - len(empty),
              "fixture does not separate per-snapshot and aggregate limits")
    cache_refusal(session.call("single-bytes-full", "read_evidence_bundle", {"length": 17}),
                  "Canonical bundle exceeds the available snapshot byte budget.")
    replay_edges(session, "empty-after-single-failure", empty_id, empty, 0)
    family.snapshot_release(session.call("release-empty", "close_evidence_snapshot", {"snapshot_id": empty_id}),
                            empty_id, True, len(empty), 0, 0)
    session.export("single-failure-keeps-evidence", workspace / "large.json", records, raw)
    return {"per_snapshot_refusals": 1, "restored_zero": True}


EXERCISES = dict(zip(SCENARIOS, (exercise_count, exercise_total, exercise_single), strict=True))


class CapacitySession(family.Session):
    def export(self, name, path, expected, expected_raw=None):
        response = self.call(name, "export_evidence_bundle", {"path": str(path), "overwrite": True})
        raw, identity = family.read_stable(path, MAX_EXPORT_BYTES)
        bundle = family.validate_bundle(parse_export(raw), expected)
        q.require(family.payload(response, target=False)["result"] == {
            "path": str(path), "bytes": len(raw), "records": len(bundle["records"]), "unknowns": 0},
            "export response differs from actual complete bytes")
        q.require(raw == family.canonical_json(bundle) and (expected_raw is None or raw == expected_raw),
                  "export changed the complete canonical bundle")
        self.state["exports"][name] = {"file": identity,
            "artifact": family.archive_raw(self.root, self.output / (name + ".bundle.json.gz"), raw)}
        return raw, bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "binary", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--build-summary", type=Path)
    parser.add_argument("--build-summary-sha256")
    args = parser.parse_args(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)),
              "explicit absolute paths are required")
    q.require(args.repo.resolve() == Path(__file__).resolve().parents[1], "execute the selected repository source")
    q.require((args.build_summary is None) == (args.build_summary_sha256 is None), "incomplete build pin")
    output = args.output_dir
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "profile": PROFILE, "qualified": False, "sessions": {}, "results": {}, "errors": []}
    monitor, sessions, exit_code = None, [], 1
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "native binary pin differs")
        report["producer_before"] = [{**q.identity(args.repo / name), "path": name} for name in FILES]
        selection = Selection(args.repo, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        source = selection.snapshot()
        report["source_before"] = q.artifact_json(output, "source-before.json", source)
        if args.build_summary is not None:
            from rea_build_evidence import capture_build
            report["build_evidence"], _ = capture_build(args.build_summary, args.build_summary_sha256,
                                                       output, source, report["binary_before"])
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        inputs = fixtures(workspace, write=True)
        report["fixtures"] = q.artifact_json(output, "fixtures.json", inputs)
        config = output / "runtime.json"
        q.write_json(config, formats.config_for(output))
        report["config"] = q.artifact_reference(config, output)
        for scenario in SCENARIOS:
            session = CapacitySession("native", scenario,
                [str(args.binary), "mcp", "--runtime-config", str(config)], {}, workspace,
                output / ("native-" + scenario), output, report)
            sessions.append(session)
            try:
                session.initialize()
                report["results"][scenario] = EXERCISES[scenario](session, inputs, workspace)
            except Exception as error:
                report["errors"].append({"scenario": scenario, "error": type(error).__name__ + ": " + str(error)})
            finally:
                session.close()
        report["fixtures_after"] = {name: q.identity(Path(item["path"])) for name, item in inputs.items()}
        report["binary_after"] = q.identity(args.binary)
        report["source_after"] = q.artifact_json(output, "source-after.json", selection.snapshot())
        report["producer_after"] = [{**q.identity(args.repo / name), "path": name} for name in FILES]
        exit_code = 0 if not report["errors"] else 1
    except BaseException as error:
        report["errors"].append({"stage": "execution", "error": type(error).__name__ + ": " + str(error)})
    finally:
        for session in sessions:
            if not session.client.closed:
                try:
                    session.close()
                except BaseException as error:
                    report["errors"].append({"stage": "close", "error": str(error)})
        if monitor is not None:
            events = monitor.stop()
            report["source_events"] = q.artifact_json(output, "source-events.json", events)
            if events != {"event_count": 0, "retained_events": [], "events_truncated": False, "errors": []}:
                exit_code = 1
        if report["errors"]:
            exit_code = 1
        report["producer_exit_code"] = exit_code
        q.write_json(output / "qualification.json", report)
    print(q.json_bytes({"report": str(output / "qualification.json"), "exit_code": exit_code,
                        "qualified": False, "scenarios_recorded": len(report["results"])}).decode(), end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
