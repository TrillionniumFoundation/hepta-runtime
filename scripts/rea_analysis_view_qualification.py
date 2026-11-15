#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Actual REA/native summary and APK analysis-view MCP comparisons.

The original 50 captured input templates are rebound once to the original
producer's fresh complete parent. The exact same raw requests and bare record
are then used for the native producer. Complete envelopes, errors, export bytes,
retention and the independently observed origin-sensitive view key order are
compared. This finite profile never qualifies the complete REA operation.
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
import rea_apk_path_alias_qualification as alias
import rea_operation_qualification as q


INPUTS_SHA256 = "e38b28a268520a9b91999437c5b743eb923d1b8c6521e5434ee2ead8baeb60f6"
ALIASES = {**a.ALIASES, "inspect_analysis_view": "rea_inspect_analysis_view"}
POSITIVE_CASES = {"retained-summary-defaults", "retained-apk-signers-defaults",
                  "retained-apk-digests-defaults", "retained-apk-lineage-numbers",
                  "retained-apk-empty-fields", "inline-valid-parent", "file-bare-record",
                  "file-exported-bundle", "file-exported-bundle-exact"}
OPEN_REQUIREMENTS = ["other-analysis-view-kinds", "complete-evidence-import-profiles",
                     "active-cancellation-and-owner-drain", "all-resource-and-oversize-boundaries",
                     "complete-build-source-attestation", "nonlocal-and-cross-platform-contracts"]


def materialize_cases(templates, parent, workspace):
    """Rebind inputs once; never rewrite an observed response to obtain a match."""
    q.require(len(templates) == 50 and len({case["name"] for case in templates}) == 50,
              "frozen 50-case input set is incomplete")
    original = next(case["arguments"]["source"]["evidence"] for case in templates
                    if case["name"] == "inline-valid-parent")
    q.require(original["evidence_id"] == q.semantic_evidence_id(original),
              "frozen parent semantic identifier is invalid")
    q.require(parent["evidence_id"] == q.semantic_evidence_id(parent),
              "fresh original parent semantic identifier is invalid")
    old_root = str(Path(original["parameters"]["path"]).parent)
    new_root = str(workspace)
    old_id, new_id = original["evidence_id"], parent["evidence_id"]

    def rebind(value):
        if isinstance(value, str):
            return value.replace(old_root, new_root).replace(old_id, new_id)
        if isinstance(value, list):
            return [rebind(item) for item in value]
        if isinstance(value, dict):
            return {key: rebind(item) for key, item in value.items()}
        return value

    q.require(rebind(original) == parent, "fresh original parent changed beyond paths and semantic identity")
    result = []
    for template in templates:
        raw = template["raw_arguments"]
        q.require(q.parse_json(raw.encode()) == template["arguments"], "frozen raw input disagrees")
        raw = raw.replace(a.encoded(old_root)[1:-1], a.encoded(new_root)[1:-1]).replace(old_id, new_id)
        arguments = rebind(template["arguments"])
        q.require(q.parse_json(raw.encode()) == arguments, "rebinding changed raw input semantics")
        result.append({"id": template["name"], "arguments": arguments, "raw_arguments": raw})
    q.require(next(case["arguments"]["source"]["evidence"] for case in result
                   if case["id"] == "inline-valid-parent") == parent, "inline fixture differs from original parent")
    return result


def view_order(value):
    """Capture an explicit protocol ordering fact before JSON archival sorts keys."""
    if value.get("isError") or "rpc_error" in value or "structuredContent" not in value:
        return []
    body = value["structuredContent"]
    text = value["content"][0]["text"]
    if body.get("operation") == "inspect_analysis_view":
        records, text_records = [body], [text]
    elif isinstance(body.get("result"), dict) and isinstance(body["result"].get("records"), list):
        records, text_records = body["result"]["records"], text["result"]["records"]
    else:
        return []
    q.require(len(records) == len(text_records), "text/structured bundle lengths disagree")
    facts = []
    for record, textual in zip(records, text_records):
        if record.get("operation") != "inspect_analysis_view":
            continue
        parameters = record["parameters"]["view"]
        text_parameters = textual["parameters"]["view"]
        facts.append({"evidence_id": record["evidence_id"], "structured_keys": list(parameters),
                      "text_keys": list(text_parameters)})
    return facts


class Session:
    def __init__(self, client, label, output):
        self.client, self.label, self.output = client, label, output
        self.rows, self.checks = [], []

    def check(self, name, function):
        try:
            function()
            self.checks.append({"id": name, "status": "PASS"})
        except (q.QualificationError, KeyError, TypeError, ValueError) as error:
            self.checks.append({"id": name, "status": "FAIL", "error": str(error)})

    def call(self, name, operation, arguments, raw=None):
        tool = ALIASES[operation] if self.label == "native" else operation
        raw = a.encoded(arguments) if raw is None else raw
        q.require(q.parse_json(raw.encode()) == arguments, "request/raw disagreement")
        params = {"name": tool, "arguments": arguments}
        raw_params = ('{"name":' + a.encoded(tool) + ',"arguments":' + raw + '}').encode()
        started = time.monotonic()
        response = self.client.request("tools/call", params, raw_params)
        value = q.tool_value(response)
        row = {"id": name, "operation": operation, "arguments": arguments, "raw_arguments": raw,
               "response": response, "value": value, "view_order": view_order(value),
               "seconds": time.monotonic() - started}
        self.rows.append(row)
        q.write_json(self.output / (str(len(self.rows)).zfill(3) + "-" + name + ".json"), row)
        return value


def verify_retained(session, parent):
    observed = {parent["evidence_id"]: parent}
    for row in session.rows:
        if row["operation"] != "inspect_analysis_view":
            continue
        value = row["value"]
        expected_success = row["id"] in POSITIVE_CASES
        q.require((not value.get("isError") and "rpc_error" not in value) == expected_success,
                  "captured positive/error split differs for " + row["id"])
        if expected_success:
            record = a.payload(value)
            q.require(record["evidence_id"] == q.semantic_evidence_id(record), "derived semantic ID differs")
            old = observed.get(record["evidence_id"])
            q.require(old is None or old == record, "same ID changed semantic record")
            observed.setdefault(record["evidence_id"], record)
    q.require(len(observed) == 6, "the fixed profile did not produce exactly parent plus five unique views")
    bundle = a.complete_bundle(session.rows[-1]["value"])
    q.require(bundle["records"] == sorted(observed.values(), key=lambda record: record["evidence_id"]),
              "final retained records differ from full observed parent/derived records")


def verify_origin(session, order):
    parent = a.payload(session.rows[0]["value"])
    first, second = (a.payload(row["value"]) for row in session.rows[1:3])
    bundle = a.complete_bundle(session.rows[3]["value"])
    q.require(first == second and first["evidence_id"] == q.semantic_evidence_id(first),
              "equivalent origins changed the semantic record or identifier")
    q.require(bundle["records"] == sorted((parent, first), key=lambda record: record["evidence_id"]),
              "same-ID origins did not retain exactly parent plus one derived record")
    expected = {"direct-apk": ["kind", "offset", "limit", "collection"],
                "analysis-view": ["offset", "limit", "collection", "kind"]}
    for row, origin in zip(session.rows[1:3], order):
        facts = row["view_order"]
        q.require(len(facts) == 1 and facts[0]["structured_keys"] == expected[origin]
                  and facts[0]["text_keys"] == expected[origin], "current response used the retained origin's order")
    retained = session.rows[3]["view_order"]
    q.require(len(retained) == 1 and retained[0]["structured_keys"] == expected[order[0]]
              and retained[0]["text_keys"] == expected[order[0]], "same-ID retain replaced first origin order")


def compare_sessions(report, scenario, left, right):
    q.require([row["id"] for row in left.rows] == [row["id"] for row in right.rows],
              "session request sequence differs")
    for original, native in zip(left.rows, right.rows):
        q.require(original["raw_arguments"] == native["raw_arguments"], "producers received different raw inputs")
        differences = a.differences(original["value"], native["value"])
        differences += a.differences(original["view_order"], native["view_order"], "$/view_order")
        if "export_file" in original:
            differences += a.differences(original["export_file"], native.get("export_file"), "$/export_file")
        report["comparisons"].append({"id": scenario + "/" + original["id"],
                                       "status": "PASS" if not differences else "FAIL", "differences": differences})


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "build-summary", "source-checkpoint", "reference-package",
                 "reference-tarball", "node", "output-dir", "fixture-repo", "reference-inputs"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)), "all paths must be absolute")
    output = args.output_dir
    q.require(not output.exists(), "refusing to overwrite an evidence directory")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": "hepta.rea.analysis-view-mcp.v1", "qualified": False, "status": "OPEN",
              "scope": "Frozen 50 inputs, summary/APK views, complete source records and observed origin order; finite Linux profile",
              "open_requirements": OPEN_REQUIREMENTS, "sessions": {}, "comparisons": [], "errors": []}
    monitor = selection = None
    sessions = {}
    cases = original_parent = None
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "wrong frozen binary")
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["node"] = q.identity(args.node.resolve())
        q.require(report["node"]["sha256"] == a.NODE_SHA256, "unexpected Node binary")
        report["node_version"] = subprocess.check_output([str(args.node), "--version"], env={}, timeout=10, text=True).strip()
        q.require(report["node_version"] == "v22.23.4", "unexpected Node version")
        for name, path in (("build-summary", args.build_summary), ("source-checkpoint", args.source_checkpoint),
                           ("original-inputs", args.reference_inputs)):
            raw = path.read_bytes()
            if name == "original-inputs":
                q.require(hashlib.sha256(raw).hexdigest() == INPUTS_SHA256, "original input templates changed")
                templates = q.parse_json(raw)
            with (output / (name + ".json")).open("xb") as handle:
                handle.write(raw)
            report[name] = q.artifact_reference(output / (name + ".json"), output)
        from rea_full_qualification import Selection, SourceMonitor
        selection = Selection(Path(__file__).resolve().parents[1], output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        q.write_json(output / "producer-before.json", before)
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        apk = workspace / "rotation-v31.apk"
        raw = (args.fixture_repo / "tests/fixtures/rea_apk_signature/rotation-v31.apk").read_bytes()
        q.require(len(raw) == 12375 and hashlib.sha256(raw).hexdigest() == alias.FIXTURE_SHA256, "frozen APK changed")
        with apk.open("xb") as handle:
            handle.write(raw)
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
                             "hosts": {"never-connect": {"ssh_target": "never-connect-invalid",
                                       "remote_state_dir": str(output / "unused-remote"), "allow_execute": False,
                                       "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        producers = (("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], env),
                     ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}))

        def start(label, scenario, command, environment):
            directory = output / (label + "-" + scenario)
            client = q.Mcp(command, workspace, environment, directory)
            session = Session(client, label, directory)
            sessions[(label, scenario)] = session
            report["sessions"][label + "/" + scenario] = {"rows": session.rows, "checks": session.checks}
            client.initialize()
            return session

        def close(label, scenario, session):
            state = report["sessions"][label + "/" + scenario]
            state["close"] = session.client.close()
            q.require(a.closed_normally(state["close"]), label + "/" + scenario + " owner did not drain")

        for label, command, environment in producers:
            session = start(label, "main", command, environment)
            state = report["sessions"][label + "/main"]
            state["catalog"] = session.client.tools()
            parent = a.payload(session.call("seed", "inspect_apk_signature", {"path": str(apk), "detail": "complete"}))
            if label == "reference":
                original_parent = parent
                cases = materialize_cases(templates, parent, workspace)
                q.write_json(output / "materialized-inputs.json", cases)
                q.write_json(workspace / "record.json", parent)
                report["bare_record"] = q.identity(workspace / "record.json")
            else:
                session.check("original-parent-equality", lambda: q.require(parent == original_parent, "native complete seed differs"))
            bundle_file = workspace / "bundle.json"
            session.call("export-source", "export_evidence_bundle", {"path": str(bundle_file)})
            observed_file = q.identity(bundle_file)
            exported_bytes = bundle_file.read_bytes()
            q.require(q.identity(bundle_file) == observed_file, "export source changed during capture")
            with (session.output / "exported-source-bundle.json").open("xb") as handle:
                handle.write(exported_bytes)
            session.rows[-1]["export_file"] = {"path": str(bundle_file), "bytes": len(exported_bytes),
                                               "sha256": hashlib.sha256(exported_bytes).hexdigest()}
            bundle_before = session.call("bundle-before", "get_evidence_bundle", {})
            session.check("complete-export-source", lambda: q.require(q.parse_json(exported_bytes) == a.complete_bundle(bundle_before)
                          and a.complete_bundle(bundle_before)["records"] == [parent], "exported source differs from the sole complete parent"))
            for case in cases:
                session.call(case["id"], "inspect_analysis_view", case["arguments"], case["raw_arguments"])
            session.call("bundle-after", "get_evidence_bundle", {})
            session.check("complete-retained-views", lambda: verify_retained(session, parent))
            close(label, "main", session)
            q.require(q.identity(bundle_file) == observed_file, "refusing to remove changed owned export")
            bundle_file.unlink()
            state["removed_owned_export"] = observed_file

            cold = start(label, "cold", command, environment)
            empty = cold.call("empty", "get_evidence_bundle", {})
            cold.check("new-session-empty", lambda: q.require(all(not value for value in a.complete_bundle(empty).values()), "retention leaked to a new session"))
            absent = cold.call("retained-unavailable", "inspect_analysis_view", {
                "source": {"kind": "retained-evidence", "evidence_id": original_parent["evidence_id"]}, "view": {"kind": "summary"}})
            cold.check("new-session-parent-unavailable", lambda: q.require(absent.get("isError") is True
                       and absent["content"][0]["text"]["error"]["code"] == "evidence_integrity_mismatch", "old session parent remained available"))
            close(label, "cold", cold)

            for order in (("direct-apk", "analysis-view"), ("analysis-view", "direct-apk")):
                scenario = "-then-".join(order)
                origin = start(label, scenario, command, environment)
                origin.call("seed", "inspect_apk_signature", {"path": str(apk), "detail": "complete"})
                for operation in order:
                    if operation == "direct-apk":
                        origin.call(operation, "inspect_apk_signature", {"path": str(apk), "view": {"collection": "signers"}})
                    else:
                        origin.call(operation, "inspect_analysis_view", {
                            "source": {"kind": "retained-evidence", "evidence_id": original_parent["evidence_id"]},
                            "view": {"kind": "apk-signature", "collection": "signers"}})
                origin.call("retained", "get_evidence_bundle", {})
                origin.check("same-id-current-response-first-retained-order", lambda: verify_origin(origin, order))
                close(label, scenario, origin)

        for scenario in ("main", "cold", "direct-apk-then-analysis-view", "analysis-view-then-direct-apk"):
            compare_sessions(report, scenario, sessions[("reference", scenario)], sessions[("native", scenario)])
        original_catalog = {tool["name"]: tool for tool in report["sessions"]["reference/main"]["catalog"]}
        native_catalog = {tool["name"]: tool for tool in report["sessions"]["native/main"]["catalog"]}
        for field in ("inputSchema", "outputSchema", "annotations"):
            differences = a.differences(original_catalog.get("inspect_analysis_view", {}).get(field),
                                        native_catalog.get("rea_inspect_analysis_view", {}).get(field))
            report["comparisons"].append({"id": "registration/" + field, "differences": differences,
                                           "status": "PASS" if not differences and "inspect_analysis_view" in original_catalog
                                           and "rea_inspect_analysis_view" in native_catalog else "FAIL"})
        report["binary_after"] = q.identity(args.binary)
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["binary_before"] == report["binary_after"] and report["reference_before"] == report["reference_after"], "binary or reference changed")
        q.require(q.identity(workspace / "record.json") == report["bare_record"] and q.file_hash(apk) == alias.FIXTURE_SHA256, "input artifact changed")
        after = selection.snapshot()
        q.write_json(output / "producer-after.json", after)
        q.require(before == after, "qualification producer changed")
    except BaseException as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        for (label, scenario), session in sessions.items():
            state = report["sessions"][label + "/" + scenario]
            if "close" not in state:
                try:
                    state["close"] = session.client.close()
                except BaseException as error:
                    report["errors"].append(label + "/" + scenario + " close: " + repr(error))
            for name in ("wire.jsonl", "launch.json", "close.json", "stderr.log"):
                path = session.output / name
                if path.exists():
                    state[name] = q.artifact_reference(path, output)
            if "close" not in state or not a.closed_normally(state["close"]):
                report["errors"].append(label + "/" + scenario + " owner cleanup incomplete")
        if monitor is not None:
            observed = monitor.stop()
            q.write_json(output / "producer-monitor.json", observed)
            if observed["event_count"] or observed["errors"]:
                report["errors"].append("producer source monitor changed or lost coverage")
        checks = [check for session in sessions.values() for check in session.checks]
        report["failed_independent_checks"] = [check for check in checks if check["status"] != "PASS"]
        report["passed_comparisons"] = sum(row["status"] == "PASS" for row in report["comparisons"])
        report["failed_comparisons"] = sum(row["status"] != "PASS" for row in report["comparisons"])
        report["case_counts"] = {label + "/" + scenario: len(session.rows) for (label, scenario), session in sessions.items()}
        expected = {label + "/" + scenario: count for label in ("reference", "native")
                    for scenario, count in (("main", 54), ("cold", 2), ("direct-apk-then-analysis-view", 4), ("analysis-view-then-direct-apk", 4))}
        complete = len(report["comparisons"]) == 67 and report["case_counts"] == expected
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
