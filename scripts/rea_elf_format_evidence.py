#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently replay a finite public ELF format receipt without execution."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re

import rea_build_evidence as build
import rea_elf_format_fixtures as fixtures
import rea_elf_format_qualification as producer
import rea_operation_evidence as e
import rea_operation_qualification as q
from rea_full_qualification import Selection


def observed_identity(item):
    q.require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}
              and Path(item["path"]).is_absolute() and type(item["bytes"]) is int and item["bytes"] > 0
              and isinstance(item["sha256"], str) and re.fullmatch("[0-9a-f]{64}", item["sha256"]),
              "invalid selected executable identity")
    return item


def validate_report(repo, receipt_path, expected_sha256):
    repo, receipt_path = Path(repo), Path(receipt_path)
    q.require(repo.is_absolute() and receipt_path.is_absolute(), "explicit absolute paths are required")
    root = receipt_path.parent
    raw = build.read_regular(root, receipt_path.name, q.MAX_WIRE_BYTES)
    q.require(hashlib.sha256(raw).hexdigest() == expected_sha256, "format receipt digest differs")
    report = q.parse_json(raw)
    q.require(report["schema"] == producer.SCHEMA and report["profile"] == fixtures.PROFILE
              and report["operation"] == "inspect_elf_notes", "unreviewed format profile")
    q.require(report["errors"] == [], "format producer recorded failed expectations or incomplete execution")
    workspace = Path(report["workspace"])
    q.require(workspace.is_absolute() and workspace.name == "workspace", "invalid fixture workspace")
    expected = fixtures.corpus(workspace)
    q.require(q.json_equal(e.artifact_json(root, report["manifest"]), expected), "reviewed corpus differs")
    q.require(q.json_equal(report["fixtures_after"], expected["fixtures"]), "fixture bytes changed")
    for name, item in expected["fixtures"].items():
        raw_fixture = build.read_regular(root, "workspace/" + name + ".elf", 65536)
        q.require(len(raw_fixture) == item["bytes"] and hashlib.sha256(raw_fixture).hexdigest() == item["sha256"],
                  "archived fixture bytes differ from the regenerated corpus: " + name)
    q.require(q.json_equal(e.artifact_json(root, report["config"]), producer.config_for(workspace.parent)),
              "runtime permissions differ from the reviewed private fixture profile")
    bindings = report["producer_before"]
    q.require([item["path"] for item in bindings] == list(producer.FILES)
              and q.json_equal(bindings, report["producer_after"]), "producer source changed or is incomplete")
    for item in bindings:
        e.read_artifact(repo, item)
    source = e.artifact_json(root, report["source_before"])
    q.require(source == e.artifact_json(root, report["source_after"])
              and source == Selection(repo, root / "unused-target", root).snapshot(),
              "format execution is not from the selected source combination")
    q.require(e.artifact_json(root, report["source_events"]) == {
        "event_count": 0, "retained_events": [], "events_truncated": False, "errors": []},
        "source monitoring changed or lost coverage")
    reference = report["reference_before"]
    q.require(reference == report["reference_after"], "original package changed")
    for key, value in {"name": "rea-agents", "version": "6.8.0", "file_count": 2398,
                       "tarball_sha256": q.PACKAGE_SHA256, "files_sha256": q.PACKAGE_FILES_SHA256,
                       "catalog_sha256": q.CATALOG_SHA256, "git_source_commit": q.REFERENCE_COMMIT}.items():
        q.require(reference[key] == value, "unfrozen original identity: " + key)
    native = observed_identity(report["native_before"])
    node = observed_identity(report["node_before"])
    q.require(native == report["native_after"] and node == report["node_after"]
              and node["sha256"] == producer.NODE_SHA256 and report["node_version"] == "v22.23.4",
              "selected executable changed or has an unreviewed identity")
    binding = None
    if report.get("build_evidence") is not None:
        binding = build.validate_bundle(root, report["build_evidence"], source, native)
    q.require(set(report["sessions"]) == {"reference", "native"}, "required owner sessions differ")
    wires, tools, owners = {}, {}, []
    for label, session in report["sessions"].items():
        wires[label] = e.wire_index(e.read_artifact(root, session["wire"]))
        tools[label] = e.artifact_json(root, session["tools"])
        e.bind_tools(wires[label], tools[label])
        launch, close = (e.artifact_json(root, session[field]) for field in ("launch", "close"))
        e.bind_owner(launch, close)
        q.require(e.owner_closed(close), "format owner did not close without forced cleanup")
        q.require(launch["cwd"] == str(workspace), "MCP launched outside the fixture workspace")
        if label == "reference":
            q.require(launch["argv"] == [node["path"], str(Path(reference["package_root"]) / "scripts/rea.mjs"), "mcp"]
                      and launch["environment"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                          "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"},
                      "the frozen full-schema original entry point was not used")
        else:
            q.require(launch["argv"] == [native["path"], "mcp", "--runtime-config", str(workspace.parent / "runtime.json")]
                      and launch["environment"] == {}, "native launch profile differs")
        owners.append(launch["owner"])
    q.require(owners[0] != owners[1] and len(tools["reference"]) == 229, "owner/catalog identity differs")
    q.compare_registration(tools["reference"], tools["native"])
    cases = expected["cases"]
    q.require([row["id"] for row in report["cases"]] == [case["id"] for case in cases],
              "case set/order is missing, repeated or invented")
    comparisons, retained = {}, {}
    for case, row in zip(cases, report["cases"], strict=True):
        replies = {label: e.artifact_json(root, row[label]) for label in wires}
        for label, response in replies.items():
            e.bind_call(wires[label], response, "inspect_elf_notes" if label == "reference" else "rea_inspect_elf_notes",
                        case["arguments"])
            record = producer.check_case(case, response)
            if label == "reference" and record is not None:
                retained[record["evidence_id"]] = record
        value = e.response_comparisons(replies["reference"], replies["native"], wires["reference"], wires["native"])
        comparisons[case["id"]] = {**value, "category": case["category"], "expected_outcome": case["kind"],
                                   "passed": value["opaque_response_equal"] and value["parsed_result_equal"]}
    replies = {label: e.artifact_json(root, report["retention"][label]) for label in wires}
    for label, response in replies.items():
        e.bind_call(wires[label], response, "get_evidence_bundle" if label == "reference" else "rea_get_evidence_bundle", {})
        q.check_retention_response({"arguments": {}}, response, list(retained.values()))
        calls = [message for message in wires[label]["sent"].values() if message.get("method") == "tools/call"]
        q.require(len(calls) == len(cases) + 1, "unaccounted public calls changed this finite observation")
    retention = e.response_comparisons(replies["reference"], replies["native"], wires["reference"], wires["native"])
    passed = all(row["passed"] for row in comparisons.values()) and retention["opaque_response_equal"]
    return {"schema": "hepta.rea.elf-format-assessment.v2", "profile": fixtures.PROFILE,
            "finite_status": "PASS" if passed else "FAIL", "qualified": False,
            "scope": "the regenerated finite public ELF corpus; no whole-operation ledger promotion",
            "receipt_sha256": expected_sha256, "cases": comparisons, "retention": retention,
            "normal_owner_closes": 2, "source_tree_sha256": source["tree_sha256"],
            "native_binary_sha256": native["sha256"], "build_source_binding": binding}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    result = validate_report(args.repo, args.report, args.sha256)
    print(q.json_bytes(result).decode(), end="")
    return 0 if result["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
