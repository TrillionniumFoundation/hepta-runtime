#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Actual frozen REA/native APK and export MCP comparisons; never full parity.

The two producers run sequentially against identical private paths. Only the
export files created by this run are removed between producers, after preserving
their exact bytes and observing normal process shutdown. No output field is
discarded to make comparisons pass. The immutable binary/build identities are
recorded; the currently editable integration tree is not claimed as a build.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import rea_operation_qualification as q


PINS = {
    "apk_inputs": "166867f7b33f2095ccaecc0e32b3d1674172c8aa07ec1331ab85a0957aad1878",
    "apk_compact": "bfd515e04f320572216c4b0dcf9ea9c9f8893e8b1d3921c11886031bb59de651",
    "apk_successes": "88abca38d36db24fd58302e82f1068cdbe8c6e41ab78f8081a2c7cdc67fcf736",
    "apk_errors": "c92c496d1a549899c3ed4c4a622cc3c92485e21635d208945e8d0304bd59839b",
    "export_inputs": "4cea42d0a776fab0d28be8f63e01035216e2dce1535c006610bd18b426e95a81",
    "export_original": "c27452d54c4fdfc198127a242254b1bfab5de162fdabf783f3031f2bc2632a32",
}
NODE_SHA256 = "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
BUNDLE_KEYS = {"artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records"}
ALIASES = {"inspect_apk_signature": "rea_inspect_apk_signature_evidence",
           "get_evidence_bundle": "rea_get_evidence_bundle",
           "export_evidence_bundle": "rea_export_evidence_bundle"}
EXPECTED_CASE_COUNTS = {"export": 23, "input": 297, "error": 25, "positive": 16, "flow": 7}
OPEN_REQUIREMENTS = ["retained-inspect_analysis_view-recovery-route",
                     "active-cancellation-and-owner-drain", "worker-deadline-and-owner-drain",
                     "all-frozen-format-error-and-capacity-boundaries",
                     "oversized-export-retention-and-cleanup-failure-retry",
                     "complete-build-source-attestation", "nonlocal-filesystem-and-platform-contracts"]


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def rebase(value, old, new):
    """Bind old fixture paths to this run's private namespace; not a comparator."""
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [rebase(v, old, new) for v in value]
    if isinstance(value, dict):
        return {k: rebase(v, old, new) for k, v in value.items()}
    return value


def replace_root_path(raw, new_path):
    """Change only the root path token; retain numeric spellings/property order."""
    original = q.parse_json(raw.encode())
    q.require(isinstance(original, dict) and "path" in original, "missing root path token")
    decoder = json.JSONDecoder()
    position = raw.index("{") + 1
    while True:
        while raw[position].isspace():
            position += 1
        key, end = decoder.raw_decode(raw, position)
        position = end
        while raw[position].isspace():
            position += 1
        q.require(raw[position] == ":", "malformed root member")
        position += 1
        while raw[position].isspace():
            position += 1
        _, end = decoder.raw_decode(raw, position)
        if key == "path":
            result = raw[:position] + encoded(new_path) + raw[end:]
            expected = {**original, "path": new_path}
            q.require(q.parse_json(result.encode()) == expected, "path rebinding changed other input")
            return result
        position = end
        while raw[position].isspace():
            position += 1
        q.require(raw[position] == ",", "root path not found")
        position += 1


def ordered_arguments(arguments, keys):
    q.require(len(keys) == len(set(keys)) and set(keys) == set(arguments),
              "original property order is incomplete or duplicated")
    return {key: arguments[key] for key in keys}


def differences(left, right, path="$"):
    if isinstance(left, dict) and isinstance(right, dict):
        result = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append({"path": path + "/" + key,
                               "reference_present": key in left, "native_present": key in right,
                               "reference": left.get(key), "native": right.get(key)})
            else:
                result.extend(differences(left[key], right[key], path + "/" + key))
        return result
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        return [d for i, (a, b) in enumerate(zip(left, right))
                for d in differences(a, b, path + "/" + str(i))]
    # JSON numbers have numeric semantics; boolean and number are distinct.
    numeric = isinstance(left, (int, float)) and not isinstance(left, bool)
    numeric = numeric and isinstance(right, (int, float)) and not isinstance(right, bool)
    if left == right and (type(left) is type(right) or numeric):
        return []
    return [{"path": path, "reference": left, "native": right}]


def stamp(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def sparse_copy(source, destination, expected_bytes, expected_sha256):
    """Hash every input byte; avoid allocating the 512 MiB all-zero size fixture."""
    before = source.lstat()
    q.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "fixture is not a private regular file")
    q.require(before.st_size == expected_bytes, "fixture length changed")
    h = hashlib.sha256()
    count = 0
    with source.open("rb") as src, destination.open("xb") as dst:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            count += len(block)
            h.update(block)
            if block == bytes(len(block)):
                dst.seek(len(block), os.SEEK_CUR)
            else:
                dst.write(block)
        dst.truncate(count)
    q.require(count == expected_bytes and h.hexdigest() == expected_sha256, "fixture digest changed")
    q.require(stamp(source.lstat()) == stamp(before), "source fixture changed during capture")
    q.require(q.file_hash(destination) == expected_sha256, "copied fixture bytes differ")
    return q.identity(destination)


class OwnedExports:
    """Observe/save only two authorized files; no recursive or unconditional delete."""

    def __init__(self, root, output):
        self.root, self.output = root, output
        self.allowed = {root / "complete.json", root / "session-complete.json"}
        self.seen = {}

    def observe(self, label):
        result = {}
        for path in sorted(self.allowed):
            if not path.exists() and not path.is_symlink():
                result[path.name] = {"exists": False}
                continue
            before = path.lstat()
            q.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                      and before.st_uid == os.getuid() and before.st_size <= 32 * 1024 * 1024,
                      "unexpected export target identity/size")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as handle:
                q.require(stamp(os.fstat(handle.fileno())) == stamp(before), "export replaced before read")
                raw = handle.read(32 * 1024 * 1024 + 1)
            q.require(stamp(path.lstat()) == stamp(before) and len(raw) == before.st_size,
                      "export changed while capturing")
            saved = self.output / (label + "-" + path.name)
            with saved.open("xb") as handle:
                handle.write(raw)
            fact = {"exists": True, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "path": str(path), "saved": str(saved)}
            self.seen[path] = (stamp(before), fact["sha256"])
            result[path.name] = fact
        return result

    def cleanup(self):
        observations = []
        for path, (identity, digest) in sorted(self.seen.items()):
            q.require(stamp(path.lstat()) == identity and q.file_hash(path) == digest,
                      "refusing to delete changed export output")
            path.unlink()
            observations.append({"path": str(path), "sha256": digest, "removed_owned_output": True})
        q.require(all(not p.exists() and not p.is_symlink() for p in self.allowed),
                  "unobserved export output remains")
        return observations


def payload(value, target=True):
    q.require(not value.get("isError") and "rpc_error" not in value and "structuredContent" in value,
              "expected successful structured MCP result")
    if target:
        q.require(value.get("_meta") == q.TARGET_META, "target provenance missing")
    else:
        q.require("_meta" not in value, "target-content-free export carries metadata")
    return value["structuredContent"]


def complete_bundle(value):
    bundle = payload(value)["result"]
    q.require(set(bundle) == BUNDLE_KEYS and all(isinstance(bundle[k], list) for k in BUNDLE_KEYS),
              "complete bundle seven-array contract differs")
    q.require([r["evidence_id"] for r in bundle["records"]] == sorted(set(r["evidence_id"] for r in bundle["records"])),
              "retained records are not unique/sorted")
    return bundle


def closed_normally(observation):
    return (observation["returncode"] == 0 and not observation["forced_cleanup"]
            and observation["reader_stopped"] and observation["owner_pidfd_exited"]
            and observation["process_group_gone"])


def prepare(args, output):
    bindings = {}
    def load(key, path):
        raw = path.read_bytes()
        q.require(hashlib.sha256(raw).hexdigest() == PINS[key], "changed frozen case source: " + key)
        bindings[key] = q.identity(path)
        with (output / (key + ".json")).open("xb") as handle:
            handle.write(raw)
        return q.parse_json(raw)
    invalid = load("apk_inputs", args.apk_input_cases)
    compact = load("apk_compact", args.apk_input_cases.parent / "compact-goldens.json")
    positives = load("apk_successes", args.apk_service_cases)
    negative = load("apk_errors", args.apk_error_cases)
    exports = load("export_inputs", args.export_cases)
    load("export_original", args.export_cases.parent / "goldens.json")
    q.require((len(invalid), len(positives["cases"]), len(negative), len(exports["cases"])) == (297, 16, 25, 23),
              "incomplete frozen fixture sets")
    q.require(sum(c["schema_error"] for c in exports["cases"]) == 18, "changed export schema/file split")
    workspace = output / "workspace"
    workspace.mkdir(mode=0o700)
    for name in ("inputs", "fixtures", "errors", "exports"):
        (workspace / name).mkdir(mode=0o700)
    fixtures = {}
    for name, fact in positives["fixture_sources"].items():
        q.require(Path(name).name == name, "unsafe positive fixture name")
        source = args.fixture_repo / fact["repo_relative_path"]
        q.require(source.resolve().is_relative_to(args.fixture_repo.resolve()), "fixture escapes its repository")
        fixtures[name] = sparse_copy(source, workspace / "fixtures" / name, fact["bytes"], fact["sha256"])
    compact_by_id = {row[0]: row for row in compact["rows"]}
    old_input_root = str(args.apk_input_cases.parent / "workspace")
    input_cases = []
    for case in invalid:
        raw = case["raw_arguments"]
        q.require(q.parse_json(raw.encode()) == case["arguments"], "input/raw source disagreement")
        old = case["arguments"].get("path")
        if isinstance(old, str) and old.startswith(old_input_root + "/"):
            raw = replace_root_path(raw, str(workspace / "inputs") + old[len(old_input_root):])
        input_cases.append({"id": "input/" + case["id"], "raw": raw,
                            "schema_message": compact_by_id[case["id"]][4]})
    success_cases = []
    for case in positives["cases"]:
        q.require(case["fixture"] in fixtures, "unknown positive fixture")
        raw = replace_root_path(case["input_json"], fixtures[case["fixture"]]["path"])
        success_cases.append({"id": "positive/" + case["name"], "raw": raw,
                              "operation": case["expected"]["operation"]})
    error_cases = []
    for case in negative:
        source = Path(case["fixture"])
        q.require(source.parent == args.apk_error_cases.parent / "fixtures", "negative fixture escapes its declared cache")
        q.require(Path(case["name"]).name == case["name"], "unsafe negative fixture name")
        target = workspace / "errors" / (case["name"] + ".apk")
        fixtures["error/" + case["name"]] = sparse_copy(source, target, case["fixture_bytes"], case["fixture_sha256"])
        arguments = {**case["input"], "path": str(target)}
        error_cases.append({"id": "error/" + case["name"], "raw": encoded(arguments),
                            "expected_error": rebase(case["expected"], str(source), str(target))})
    export_cases = []
    old_export_root = str(args.export_cases.parent / "workspace")
    for case in exports["cases"]:
        arguments = ordered_arguments(case["arguments"], case["argument_keys"])
        arguments = rebase(arguments, old_export_root, str(workspace / "exports"))
        export_cases.append({"id": "export/" + case["name"], "raw": encoded(arguments),
                             "expected": rebase(case["expected"], old_export_root, str(workspace / "exports")),
                             "schema_error": case["schema_error"]})
    manifest = {"bindings": bindings, "fixtures": fixtures, "apk_input_cases": input_cases,
                "apk_success_cases": success_cases, "apk_error_cases": error_cases,
                "export_cases": export_cases, "schema_template": compact["template"],
                "path_binding": "Only declared old fixture roots are rebound to this run. Outputs are compared without path normalization."}
    q.write_json(output / "case-manifest.json", manifest)
    return workspace, manifest


class Session:
    def __init__(self, client, label, output, manifest):
        self.client, self.label, self.output, self.manifest = client, label, output, manifest
        self.rows, self.checks, self.failures = [], [], []
        self.exports = OwnedExports(output.parent / "workspace" / "exports", output)

    def check(self, name, function):
        try:
            function()
            self.checks.append({"id": name, "status": "PASS"})
        except (q.QualificationError, KeyError, TypeError, ValueError) as error:
            self.checks.append({"id": name, "status": "FAIL", "error": str(error)})

    def call(self, name, operation, raw):
        tool = ALIASES[operation] if self.label == "native" else operation
        arguments = q.parse_json(raw.encode())
        parameters = {"name": tool, "arguments": arguments}
        raw_parameters = ('{"name":' + encoded(tool) + ',"arguments":' + raw + '}').encode()
        started = time.monotonic()
        response = self.client.request("tools/call", parameters, raw_parameters)
        value = q.tool_value(response)
        path = self.output / (str(len(self.rows)).zfill(4) + ".json")
        q.write_json(path, {"id": name, "operation": operation, "raw_arguments": raw,
                           "request": parameters, "response": response})
        self.rows.append({"id": name, "seconds": time.monotonic() - started,
                          "response": q.artifact_reference(path, self.output.parent), "value": value})
        return value

    def run(self):
        def apk(case):
            return self.call(case["id"], "inspect_apk_signature", case["raw"])
        for case in self.manifest["export_cases"]:
            value = self.call(case["id"], "export_evidence_bundle", case["raw"])
            self.check(case["id"] + "/original-oracle", lambda: q.require(value == case["expected"], "frozen export result differs"))
            self.check(case["id"] + "/no-target-meta", lambda: q.require("_meta" not in value, "export acquired target metadata"))
            files = self.exports.observe(case["id"].replace("/", "-"))
            self.rows[-1]["export_files"] = files
        empty = self.call("empty-before-apk", "get_evidence_bundle", "{}")
        self.check("empty-before-apk", lambda: q.require(all(not v for v in complete_bundle(empty).values()), "new session was not empty"))
        for case in self.manifest["apk_input_cases"]:
            value = apk(case)
            def validate_input():
                q.require(value.get("isError") is True and "rpc_error" not in value, "expected file or schema tool error")
                error = value["content"][0]["text"]["error"]
                if case["schema_message"] is not None:
                    expected = copy.deepcopy(self.manifest["schema_template"])
                    expected["details"]["issues"][0]["message"] = case["schema_message"]
                    q.require(error == expected, "original schema error object differs")
                else:
                    q.require("do not match its advertised input schema" not in error["message"], "schema-valid input rejected at MCP schema")
            self.check(case["id"] + "/original-schema", validate_input)
        for case in self.manifest["apk_error_cases"]:
            value = apk(case)
            self.check(case["id"] + "/original-error", lambda: q.require(
                value.get("isError") is True and value["content"][0]["text"]["error"] == case["expected_error"],
                "complete original APK error object differs"))
        empty = self.call("empty-after-rejections", "get_evidence_bundle", "{}")
        self.check("empty-after-rejections", lambda: q.require(all(not v for v in complete_bundle(empty).values()), "rejected input retained a record"))
        seed = {"path": self.manifest["fixtures"]["rotation-v31.apk"]["path"]}
        derived = self.call("seed-default-summary", "inspect_apk_signature", encoded(seed))
        pair = self.call("parent-and-derived", "get_evidence_bundle", "{}")
        observed_records = {}
        def retained_pair():
            records = complete_bundle(pair)["records"]
            q.require(len(records) == 2 and {r["operation"] for r in records} == {"inspect_apk_signature", "inspect_analysis_view"},
                      "summary did not retain both parent and derived Evidence")
            child = payload(derived)
            q.require(any(r == child for r in records), "derived Evidence was not retained in full")
            for record in records:
                q.require(record["evidence_id"] == q.semantic_evidence_id(record), "retained semantic ID mismatch")
                observed_records[record["evidence_id"]] = record
        self.check("parent-and-derived", retained_pair)
        for case in self.manifest["apk_success_cases"]:
            value = apk(case)
            def success():
                record = payload(value)
                q.require(record["operation"] == case["operation"], "complete/derived operation mismatch")
                q.require(record["evidence_id"] == q.semantic_evidence_id(record), "independent Evidence ID mismatch")
                previous = observed_records.get(record["evidence_id"])
                q.require(previous is None or previous == record, "same semantic ID changed its record")
                observed_records[record["evidence_id"]] = record
            self.check(case["id"] + "/complete-evidence", success)
        bundle_value = self.call("complete-session-bundle", "get_evidence_bundle", "{}")
        self.check("complete-session-retention", lambda: q.require(
            complete_bundle(bundle_value)["records"] == sorted(observed_records.values(), key=lambda r: r["evidence_id"]),
            "retained complete records differ from observed parent/derived Evidence"))
        export_path = self.exports.root / "session-complete.json"
        exported = self.call("export-complete-session", "export_evidence_bundle", encoded({"path": str(export_path)}))
        files = self.exports.observe("export-complete-session")
        self.rows[-1]["export_files"] = files
        def canonical_export():
            result = payload(exported, target=False)["result"]
            saved = files["session-complete.json"]
            raw = Path(saved["saved"]).read_bytes()
            bundle = complete_bundle(bundle_value)
            q.require(q.parse_json(raw) == bundle, "export does not contain the complete session bundle")
            q.require(result == {"path": str(export_path), "bytes": len(raw),
                                 "records": len(bundle["records"]), "unknowns": len(bundle["unknowns"])},
                      "export result counters/path differ from actual complete file")
        self.check("complete-session-export", canonical_export)
        after = self.call("bundle-after-export", "get_evidence_bundle", "{}")
        self.check("export-does-not-mutate-retention", lambda: q.require(after == bundle_value, "export changed session Evidence"))


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "build-summary", "source-checkpoint", "reference-package", "reference-tarball", "node",
                 "output-dir", "fixture-repo", "apk-input-cases", "apk-service-cases", "apk-error-cases", "export-cases"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)), "all paths must be absolute")
    q.require(not args.output_dir.exists(), "refusing to overwrite an evidence directory")
    output = args.output_dir
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": "hepta.rea.apk-export-mcp.v1", "qualified": False, "status": "OPEN",
              "open_requirements": OPEN_REQUIREMENTS, "sessions": {}, "comparisons": [], "errors": [],
              "scope": "Linux functional profile, immutable binary, actual original MCP; no general retained-view route qualification"}
    monitor = selection = None
    sessions = {}
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "wrong frozen native binary")
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["node"] = q.identity(args.node.resolve())
        q.require(report["node"]["sha256"] == NODE_SHA256, "unexpected Node binary")
        report["node_version"] = subprocess.check_output([str(args.node), "--version"], env={}, timeout=10, text=True).strip()
        q.require(report["node_version"] == "v22.23.4", "unexpected Node version")
        for name, path in (("build-summary", args.build_summary), ("source-checkpoint", args.source_checkpoint)):
            with (output / (name + ".json")).open("xb") as handle:
                handle.write(path.read_bytes())
            report[name] = q.artifact_reference(output / (name + ".json"), output)
        from rea_full_qualification import Selection, SourceMonitor
        producer = Path(__file__).resolve().parents[1]
        selection = Selection(producer, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        q.write_json(output / "producer-before.json", before)
        workspace, manifest = prepare(args, output)
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
                             "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(output / "unused-remote"),
                             "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        for label, command, environment in (("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], env),
                                             ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {})):
            q.require(not any((workspace / "exports").iterdir()), "export namespace is not empty before producer start")
            client = q.Mcp(command, workspace, environment, output / label)
            session = Session(client, label, output / label, manifest)
            sessions[label] = session
            state = report["sessions"][label] = {"checks": session.checks, "rows": session.rows}
            try:
                client.initialize()
                state["catalog"] = client.tools()
                session.run()
            finally:
                state["close"] = client.close()
                q.require(closed_normally(state["close"]), label + " process ownership did not drain normally")
                state["export_cleanup"] = session.exports.cleanup()
            cold = q.Mcp(command, workspace, environment, output / (label + "-cold"))
            try:
                cold.initialize()
                cold_name = ALIASES["get_evidence_bundle"] if label == "native" else "get_evidence_bundle"
                state["cold_response"] = cold.call(cold_name, {})
                q.require(all(not value for value in complete_bundle(q.tool_value(state["cold_response"])).values()),
                          label + " leaked Evidence to a new MCP session")
            finally:
                state["cold_close"] = cold.close()
                q.require(closed_normally(state["cold_close"]), label + " cold session did not drain normally")
        left, right = report["sessions"]["reference"], report["sessions"]["native"]
        original, native = ({r["name"]: r for r in state["catalog"]} for state in (left, right))
        for operation, alias in ALIASES.items():
            for field in ("inputSchema", "outputSchema", "annotations"):
                a = original.get(operation, {}).get(field)
                b = native.get(alias, {}).get(field)
                d = differences(a, b)
                report["comparisons"].append({"id": "registration/" + operation + "/" + field,
                                               "status": "PASS" if not d and operation in original and alias in native else "FAIL", "differences": d})
        q.require([r["id"] for r in left["rows"]] == [r["id"] for r in right["rows"]], "producer case sequence differs")
        for a, b in zip(left["rows"], right["rows"]):
            d = differences(a["value"], b["value"])
            row = {"id": a["id"], "status": "PASS" if not d else "FAIL", "differences": d}
            if "export_files" in a:
                q.require("export_files" in b, "missing native export observation")
                for name in a["export_files"]:
                    x, y = a["export_files"][name], b["export_files"][name]
                    if x["exists"] != y["exists"] or (x["exists"] and
                        (x["sha256"] != y["sha256"] or x["bytes"] != y["bytes"] or x["path"] != y["path"])):
                        row["status"] = "FAIL"
                        row.setdefault("export_byte_mismatches", []).append({"name": name, "reference": x, "native": y})
            report["comparisons"].append(row)
        cold_difference = differences(q.tool_value(left["cold_response"]), q.tool_value(right["cold_response"]))
        report["cold_full_envelope_equal"] = not cold_difference
        report["comparisons"].append({"id": "cold-session-isolation", "status": "PASS" if not cold_difference else "FAIL",
                                       "differences": cold_difference})
        report["binary_after"] = q.identity(args.binary)
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["binary_before"] == report["binary_after"] and report["reference_before"] == report["reference_after"], "binary or reference changed")
        after = selection.snapshot()
        q.write_json(output / "producer-after.json", after)
        q.require(before == after, "qualification producer changed")
    except BaseException as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        for label, session in sessions.items():
            state = report["sessions"][label]
            if "close" not in state:
                try:
                    state["close"] = session.client.close()
                except BaseException as error:
                    report["errors"].append(label + " close: " + repr(error))
            for name in ("wire.jsonl", "launch.json", "close.json", "stderr.log"):
                path = output / label / name
                if path.exists():
                    state[name] = q.artifact_reference(path, output)
            if "close" not in state or not closed_normally(state["close"]):
                report["errors"].append(label + " owner cleanup incomplete")
        if monitor is not None:
            observed = monitor.stop()
            q.write_json(output / "producer-monitor.json", observed)
            if observed["event_count"] or observed["errors"]:
                report["errors"].append("producer source monitor saw changes or lost coverage")
        checks = [c for state in report["sessions"].values() for c in state["checks"]]
        failures = [c for c in checks + report["comparisons"] if c["status"] != "PASS"]
        report["passed_comparisons"] = sum(c["status"] == "PASS" for c in report["comparisons"])
        report["failed_comparisons"] = sum(c["status"] != "PASS" for c in report["comparisons"])
        report["failed_independent_checks"] = [c for c in checks if c["status"] != "PASS"]
        report["expected_case_counts"] = EXPECTED_CASE_COUNTS
        report["case_counts"] = {}
        for label, state in report["sessions"].items():
            counts = {key: 0 for key in EXPECTED_CASE_COUNTS}
            for row in state["rows"]:
                key = row["id"].split("/", 1)[0] if "/" in row["id"] else "flow"
                counts[key] += 1
            report["case_counts"][label] = counts
        # Three registrations times three fields, plus one cold-session comparison.
        complete = (len(report["comparisons"]) == sum(EXPECTED_CASE_COUNTS.values()) + 10
                    and len(report["sessions"]) == 2
                    and all(counts == EXPECTED_CASE_COUNTS for counts in report["case_counts"].values()))
        report["finite_status"] = "PASS" if complete and not failures and not report["errors"] else "FAIL"
        report["status"] = "OPEN" if report["finite_status"] == "PASS" else "FAILED"
        receipt = q.write_json(output / "qualification.json", report)
        print(json.dumps({"qualified": False, "finite_status": report["finite_status"], "receipt": receipt,
                          "passed_comparisons": report["passed_comparisons"], "failed_comparisons": report["failed_comparisons"],
                          "failed_independent_checks": len(report["failed_independent_checks"]), "errors": report["errors"]}))
    return 0 if report["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"qualified": False, "status": "INVALID", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
