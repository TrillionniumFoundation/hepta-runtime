#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Finite actual MCP qualification for APK display-path and dot-alias retention.

Each scenario uses a fresh original session followed by a fresh native session
against the same private files. All response fields and the three complete
retained records are compared. Paths and semantic identifiers are never rebased
or removed from responses. Passing these eight calls does not qualify a whole
REA operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import rea_apk_export_qualification as a
import rea_operation_qualification as q


FIXTURE_SHA256 = "5127923e25443cfe023ec6ca2acdb6c188b1502665f244a2584a899d2885ee09"
EXPECTED_CALLS = ("complete-A", "summary-selected", "complete-selected", "retained")


def validate_retention(values, first_path, selected_path):
    """Independent invariants in addition to comparing the two actual producers."""
    q.require(set(values) == set(EXPECTED_CALLS), "missing sequential call")
    first = a.payload(values["complete-A"])
    child = a.payload(values["summary-selected"])
    selected = a.payload(values["complete-selected"])
    bundle = a.complete_bundle(values["retained"])
    for record, path in ((first, first_path), (selected, selected_path)):
        q.require(record["operation"] == "inspect_apk_signature", "parent operation differs")
        q.require(record["subject"]["local_path"] == path, "parent subject path was normalized")
        q.require(record["parameters"]["path"] == path, "parent parameter path was normalized")
        q.require(record["normalized_result"]["artifact"]["path"] == path,
                  "parent normalized artifact path was normalized")
    q.require(first["evidence_id"] != selected["evidence_id"],
              "distinct report paths incorrectly reused a parent semantic identifier")
    q.require(first["subject"]["digest"] == selected["subject"]["digest"],
              "same-byte fixtures produced different subject digests")
    q.require(child["operation"] == "inspect_analysis_view", "summary is not derived Evidence")
    q.require(child["subject"]["local_path"] == selected_path, "derived subject path changed")
    parent = selected["evidence_id"]
    q.require(child["parameters"] == {"parent_evidence_id": parent, "view": {"kind": "summary"}},
              "summary parameter parent or defaulted view differs")
    q.require(child["normalized_result"]["parent_evidence_id"] == parent
              and child["evidence_links"] == [parent], "summary references the first parent")
    expected = sorted((first, selected, child), key=lambda record: record["evidence_id"])
    q.require(len({record["evidence_id"] for record in expected}) == 3
              and bundle["records"] == expected, "final bundle is not exactly the three observed records")
    for record in bundle["records"]:
        q.require(record["evidence_id"] == q.semantic_evidence_id(record),
                  "independent retained Evidence semantic digest differs")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "build-summary", "source-checkpoint", "reference-package",
                 "reference-tarball", "node", "output-dir", "fixture-repo"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)),
              "all paths must be absolute")
    output = args.output_dir
    q.require(not output.exists(), "refusing to overwrite an evidence directory")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": "hepta.rea.apk-path-alias-mcp.v1", "qualified": False,
              "status": "OPEN", "scope": "Two Linux functional sequences; no whole-operation qualification",
              "sessions": {}, "comparisons": [], "errors": [],
              "open_requirements": ["complete-operation-input-and-lifecycle-coverage",
                                    "complete-build-source-attestation", "nonlocal-and-cross-platform-contracts"]}
    monitor = selection = None
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "wrong frozen binary")
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["node"] = q.identity(args.node.resolve())
        q.require(report["node"]["sha256"] == a.NODE_SHA256, "unexpected Node binary")
        report["node_version"] = subprocess.check_output([str(args.node), "--version"],
                                                         env={}, timeout=10, text=True).strip()
        q.require(report["node_version"] == "v22.23.4", "unexpected Node version")
        for name, path in (("build-summary", args.build_summary), ("source-checkpoint", args.source_checkpoint)):
            with (output / (name + ".json")).open("xb") as handle:
                handle.write(path.read_bytes())
            report[name] = q.artifact_reference(output / (name + ".json"), output)
        from rea_full_qualification import Selection, SourceMonitor
        selection = Selection(Path(__file__).resolve().parents[1], output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        q.write_json(output / "producer-before.json", before)
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        source = args.fixture_repo / "tests/fixtures/rea_apk_signature/rotation-v31.apk"
        raw = source.read_bytes()
        q.require(len(raw) == 12375 and hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256,
                  "frozen APK fixture changed")
        report["fixture_source"] = q.identity(source)
        for name in ("A.apk", "B.apk"):
            with (workspace / name).open("xb") as handle:
                handle.write(raw)
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
                             "hosts": {"never-connect": {"ssh_target": "never-connect-invalid",
                                       "remote_state_dir": str(output / "unused-remote"),
                                       "allow_execute": False, "allow_pty": False,
                                       "allow_write": False, "allow_job_network": False}}})
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
               "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        producers = (("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], env),
                     ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}))
        for scenario, selected_path in (("display-B", str(workspace / "B.apk")),
                                        ("dot-alias", str(workspace) + "/./A.apk")):
            first_path = str(workspace / "A.apk")
            calls = (("complete-A", "inspect_apk_signature", {"path": first_path, "detail": "complete"}),
                     ("summary-selected", "inspect_apk_signature", {"path": selected_path}),
                     ("complete-selected", "inspect_apk_signature", {"path": selected_path, "detail": "complete"}),
                     ("retained", "get_evidence_bundle", {}))
            scenarios = report["sessions"][scenario] = {}
            for label, command, environment in producers:
                session_output = output / (scenario + "-" + label)
                client = q.Mcp(command, workspace, environment, session_output)
                state = scenarios[label] = {"rows": [], "checks": []}
                try:
                    client.initialize()
                    for name, operation, params in calls:
                        tool = a.ALIASES[operation] if label == "native" else operation
                        started = time.monotonic()
                        response = client.call(tool, params)
                        value = q.tool_value(response)
                        row = {"id": name, "operation": operation, "request": {"tool": tool, "arguments": params},
                               "response": response, "value": value, "seconds": time.monotonic() - started}
                        state["rows"].append(row)
                        q.write_json(session_output / (name + ".json"), row)
                    try:
                        validate_retention({row["id"]: row["value"] for row in state["rows"]}, first_path, selected_path)
                        state["checks"].append({"id": "three-record-path-and-identity", "status": "PASS"})
                    except (q.QualificationError, KeyError, TypeError, ValueError) as error:
                        state["checks"].append({"id": "three-record-path-and-identity", "status": "FAIL", "error": str(error)})
                finally:
                    state["close"] = client.close()
                    q.require(a.closed_normally(state["close"]), scenario + "/" + label + " owner did not drain")
                    for name in ("wire.jsonl", "launch.json", "close.json", "stderr.log"):
                        path = session_output / name
                        if path.exists():
                            state[name] = q.artifact_reference(path, output)
            left, right = scenarios["reference"], scenarios["native"]
            q.require([row["id"] for row in left["rows"]] == list(EXPECTED_CALLS)
                      and [row["id"] for row in right["rows"]] == list(EXPECTED_CALLS), "call sequence incomplete")
            for original, native in zip(left["rows"], right["rows"]):
                difference = a.differences(original["value"], native["value"])
                difference += a.differences({k: v for k, v in original["response"].items() if k != "result"},
                                            {k: v for k, v in native["response"].items() if k != "result"}, "$/rpc")
                report["comparisons"].append({"id": scenario + "/" + original["id"],
                                               "status": "PASS" if not difference else "FAIL", "differences": difference})
        report["binary_after"] = q.identity(args.binary)
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["binary_before"] == report["binary_after"]
                  and report["reference_before"] == report["reference_after"], "producer binary or reference changed")
        q.require(all(q.file_hash(workspace / name) == FIXTURE_SHA256 for name in ("A.apk", "B.apk")),
                  "input fixture changed")
        after = selection.snapshot()
        q.write_json(output / "producer-after.json", after)
        q.require(before == after, "qualification producer changed")
    except BaseException as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        if monitor is not None:
            observed = monitor.stop()
            q.write_json(output / "producer-monitor.json", observed)
            if observed["event_count"] or observed["errors"]:
                report["errors"].append("producer source monitor saw changes or lost coverage")
        checks = [check for scenarios in report["sessions"].values() for session in scenarios.values()
                  for check in session["checks"]]
        report["failed_independent_checks"] = [check for check in checks if check["status"] != "PASS"]
        report["passed_comparisons"] = sum(row["status"] == "PASS" for row in report["comparisons"])
        report["failed_comparisons"] = sum(row["status"] != "PASS" for row in report["comparisons"])
        complete = len(report["comparisons"]) == 8 and len(checks) == 4
        report["finite_status"] = "PASS" if complete and not report["failed_comparisons"] and not report["failed_independent_checks"] and not report["errors"] else "FAIL"
        report["status"] = "OPEN" if report["finite_status"] == "PASS" else "FAILED"
        receipt = q.write_json(output / "qualification.json", report)
        print(json.dumps({"qualified": False, "finite_status": report["finite_status"], "receipt": receipt,
                          "passed_comparisons": report["passed_comparisons"], "failed_comparisons": report["failed_comparisons"],
                          "failed_independent_checks": report["failed_independent_checks"], "errors": report["errors"]}))
    return 0 if report["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"qualified": False, "status": "INVALID", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
