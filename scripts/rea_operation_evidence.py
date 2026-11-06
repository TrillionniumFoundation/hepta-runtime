#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Read-only, fail-closed consumption of reviewed operation qualification receipts.

The optional repository index pins original receipts by digest. Status and PASS
fields in those receipts are never authorities: comparisons are replayed from
the complete request/response wires, independent fixture facts and current
reviewed profile. These local artifacts are provenance, not a cryptographic
proof against a malicious operator with write access to the repository.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys


INDEX_PATH = "docs/rea-native/compatibility/REA_6_8_0_QUALIFICATIONS.json"
INDEX_SCHEMA = "hepta.rea.operation-qualifications.v1"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def _module(name):
    # This explicit local source file is part of the reviewed repository, not
    # a module named by an input receipt or a system-wide Python package.
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


q = _module("rea_operation_qualification")


def contained_path(root, relative):
    q.require(isinstance(relative, str) and relative, "empty evidence artifact path")
    parts = PurePosixPath(relative).parts
    q.require(not PurePosixPath(relative).is_absolute() and ".." not in parts
              and "\\" not in relative and ":" not in relative, "unsafe evidence artifact path")
    path = Path(root)
    for part in parts:
        path = path / part
        q.require(not path.is_symlink(), "symlink in evidence artifact path")
    q.require(path.resolve().is_relative_to(Path(root).resolve()), "evidence artifact escapes its root")
    return path


def read_artifact(root, reference, maximum=MAX_ARTIFACT_BYTES):
    q.require(isinstance(reference, dict) and set(reference) == {"path", "bytes", "sha256"},
              "evidence reference must pin path, size and digest only")
    q.require(type(reference["bytes"]) is int and 0 <= reference["bytes"] <= maximum,
              "evidence artifact size outside allowance")
    q.require(re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is not None,
              "invalid evidence artifact digest")
    path = contained_path(root, reference["path"])
    metadata = path.stat()
    q.require(stat.S_ISREG(metadata.st_mode) and metadata.st_size == reference["bytes"],
              "evidence artifact size/type mismatch")
    raw = path.read_bytes()
    q.require(len(raw) == reference["bytes"] and hashlib.sha256(raw).hexdigest() == reference["sha256"],
              "evidence artifact digest mismatch: " + reference["path"])
    return raw


def artifact_json(root, reference):
    return q.parse_json(read_artifact(root, reference, q.MAX_WIRE_BYTES))


def wire_index(raw):
    """Authenticate summaries against the original client wire, including IDs."""
    sent, received, raw_sent = {}, {}, {}
    q.require(raw.endswith(b"\n"), "unterminated wire transcript")
    for line in raw.splitlines():
        item = q.parse_json(line)
        q.require(set(item) == {"direction", "monotonic_ns", "wire_utf8"}
                  and type(item["monotonic_ns"]) is int and item["monotonic_ns"] >= 0,
                  "invalid wire record")
        direction = item["direction"]
        q.require(direction in {"sent", "received"}, "unknown wire direction")
        text = item["wire_utf8"]
        q.require(isinstance(text, str) and text.endswith("\n") and "\n" not in text[:-1],
                  "wire record is not one complete JSON line")
        value = q.parse_json(text.encode())
        q.require(value.get("jsonrpc") == "2.0", "non-JSON-RPC wire message")
        if "id" not in value:
            q.require("method" in value, "response is missing its request ID")
            continue
        identifier = value["id"]
        q.require(type(identifier) is int and identifier > 0, "invalid request ID")
        values = sent if direction == "sent" else received
        q.require(identifier not in values, "duplicate request/response ID in wire")
        if direction == "sent":
            q.require("method" in value, "client response is not supported by this profile")
            raw_sent[identifier] = text
        else:
            q.require("method" not in value and (("result" in value) != ("error" in value)),
                      "invalid server response")
        values[identifier] = value
    q.require(set(received) <= set(sent), "wire response has no original request")
    return {"sent": sent, "received": received, "raw_sent": raw_sent}


def bind_call(wire, response, name, arguments, number_spelling=None, omit_arguments=False, argument_key_order=None):
    identifier = response.get("id")
    q.require(type(identifier) is int and q.json_equal(wire["received"].get(identifier), response),
              "case response is absent from the original wire")
    params = {"name": name}
    if not omit_arguments:
        params["arguments"] = arguments
    expected = {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": params}
    q.require(q.json_equal(wire["sent"].get(identifier), expected), "case input differs from its actual public MCP request")
    if number_spelling:
        field, spelling = number_spelling
        raw = wire["raw_sent"][identifier]
        q.require(re.search(r'"' + re.escape(field) + r'"\s*:\s*' + re.escape(spelling) + r'(?=[,}\s])', raw),
                  "reviewed numeric spelling was not transmitted")
    if argument_key_order is not None:
        q.require(list(wire["sent"][identifier]["params"]["arguments"]) == argument_key_order,
                  "reviewed input key order was not transmitted")


def bind_tools(wire, rows):
    collected = []
    for identifier, request in wire["sent"].items():
        if request.get("method") != "tools/list":
            continue
        response = wire["received"].get(identifier, {})
        q.require("result" in response and isinstance(response["result"].get("tools"), list),
                  "tools/list is incomplete in the original wire")
        collected.extend(response["result"]["tools"])
    q.require(q.json_equal(collected, rows), "tool schema summary differs from its original tools/list wire")


def case_results(cases, observed, root, reference_wire, native_wire):
    expected_ids = [case["id"] for case in cases]
    q.require(isinstance(observed, list) and [item.get("id") for item in observed] == expected_ids,
              "required case set/order is missing, duplicated or invented")
    results, retained = {}, {}
    for case, row in zip(cases, observed, strict=True):
        # No field named status, comparison, passed or qualified is consulted.
        left = artifact_json(root, row["reference"])
        right = artifact_json(root, row["native"])
        options = (case.get("number_spelling"), case.get("omit_arguments", False), case.get("argument_key_order"))
        bind_call(reference_wire, left, "inspect_elf_notes", case["arguments"], *options)
        bind_call(native_wire, right, "rea_inspect_elf_notes", case["arguments"], *options)
        try:
            if case["kind"] == "success":
                record = q.evidence_value(left)
                q.check_independent_facts(record, case)
                retained.setdefault(record["evidence_id"], record)
            q.compare_case(case, left, right)
            results[case["id"]] = {"passed": True}
        except (KeyError, TypeError, ValueError) as error:
            results[case["id"]] = {"passed": False, "error": str(error)}
    return results, retained


def valid_owner(owner):
    return (isinstance(owner, dict) and set(owner) == {"pid", "parent_pid", "process_group", "start_time_ticks"}
            and all(type(value) is int and value > 0 for value in owner.values())
            and owner["process_group"] == owner["pid"])


def bind_owner(launch, close):
    owner = launch.get("owner")
    q.require(valid_owner(owner) and type(launch.get("pid")) is int and launch["pid"] == owner["pid"]
              and valid_owner(close.get("owner")) and q.json_equal(close["owner"], owner),
              "MCP owner identity was not retained")


def owner_closed(observation):
    return (isinstance(observation, dict) and type(observation.get("returncode")) is int
            and observation["returncode"] == 0 and valid_owner(observation.get("owner"))
            and observation.get("forced_cleanup") == [] and observation.get("reader_stopped") is True
            and observation.get("owner_pidfd_exited") is True and observation.get("process_group_gone") is True
            and q.finite_number(observation.get("elapsed_seconds"))
            and 0 <= observation["elapsed_seconds"] <= q.EOF_SECONDS + 1.0)


def derive_assessment(comparisons, registration, retention, cold, open_requirements):
    """Only independently recomputed facts can close a reviewed behavior gate."""
    all_cases = bool(comparisons) and all(value["passed"] for value in comparisons.values())
    passed = ["source_package_boundary"]
    if registration and all_cases:
        passed += ["contracts", "results", "evidence"]
    if retention and cold and all_cases:
        passed += ["retention_and_pagination"]
    # These gates need actual owner cancellation/deadline and the full reviewed
    # format corpus. They stay absent until their validators are implemented.
    return {"status": "OPEN", "passed_gates": sorted(passed),
            "failed_checks": {name: value["error"] for name, value in comparisons.items() if not value["passed"]},
            "unimplemented_required_observations": list(open_requirements)}


def build_binding(root, report, source):
    """A producer's PASS/binding summary cannot replace its original artifacts."""
    bundle = report.get("build_evidence")
    if bundle is None:
        # Earlier receipts only retained one unvalidated JSON file. Preserve
        # their evidence identity without treating them as source attestation.
        if report.get("build_summary") is not None:
            read_artifact(root, report["build_summary"], q.MAX_WIRE_BYTES)
        return None
    q.require(isinstance(bundle, dict) and q.json_equal(report.get("build_summary"), bundle.get("summary")),
              "build summary differs from the retained original build bundle")
    return _module("rea_build_evidence").validate_bundle(root, bundle, source, report["native_before"])


def validate_report(repo, receipt_path, expected_sha256, snapshot=None):
    receipt_path = contained_path(repo, receipt_path)
    q.require(q.file_hash(receipt_path) == expected_sha256, "qualification receipt digest mismatch")
    root = receipt_path.parent
    report = q.parse_json(receipt_path.read_bytes())
    q.require(report.get("schema") == q.SCHEMA and report.get("profile") == q.PROFILE
              and report.get("operation") == "inspect_elf_notes", "unknown operation qualification profile")
    # The required case manifest is regenerated from reviewed source. A receipt
    # cannot quietly omit a boundary case, alter its expectation or choose a new
    # fixture with a convenient result.
    fixture_root = Path(report["workspace"])
    q.require(fixture_root.is_absolute(), "fixture workspace was not absolute")
    fixtures, cases = q.fixture_cases(fixture_root, write=False)
    q.require(q.json_equal(artifact_json(root, report["case_manifest"]), {"profile": q.PROFILE, "fixtures": fixtures, "cases": cases}),
              "case manifest differs from the reviewed independent encodings")
    bindings = report.get("producer_files")
    q.require(isinstance(bindings, list) and [item["path"] for item in bindings] == list(q.PRODUCER_FILES),
              "producer source bindings are incomplete")
    for item in bindings:
        read_artifact(repo, item)
    q.require(q.json_equal(report.get("producer_files_after"), bindings), "actual producer files changed during execution")
    executed = report.get("producer_execution_files")
    expected_scripts = [item for item in bindings if item["path"].startswith("scripts/")]
    q.require(isinstance(executed, list) and [item["repository_path"] for item in executed]
              == [item["path"] for item in expected_scripts], "actual executing profile source is not bound")
    for actual, selected in zip(executed, expected_scripts, strict=True):
        q.require(actual["sha256"] == selected["sha256"] and q.json_equal(actual["bytes"], selected["bytes"]),
                  "a different runner was executed than the selected source tree")
    before = artifact_json(root, report["source_before"])
    after = artifact_json(root, report["source_after"])
    q.require(q.json_equal(before, after) and before["tree_sha256"] == q.digest(before["files"]),
              "source inventory changed or was tampered with")
    matrix = _module("rea_full_qualification")
    current = matrix.Selection(Path(repo), root / "unused-target", root).snapshot()
    q.require(q.json_equal(current, before), "qualification was produced by a different source/fixture/profile tree")
    monitor = artifact_json(root, report["source_monitor"])
    q.require(type(monitor["event_count"]) is int and monitor["event_count"] == 0
              and monitor["errors"] == [] and monitor["retained_events"] == []
              and monitor["events_truncated"] is False, "source changed or monitor coverage was lost")
    if report["execution"]["producer_repo"] != report["execution"]["repo"]:
        monitor = artifact_json(root, report["producer_source_monitor"])
        q.require(type(monitor["event_count"]) is int and monitor["event_count"] == 0
                  and monitor["errors"] == [] and monitor["retained_events"] == []
                  and monitor["events_truncated"] is False, "actual producer changed or its monitor coverage was lost")
    reference = report["reference_before"]
    q.require(q.json_equal(reference, report["reference_after"]), "reference package changed during execution")
    for key, expected in {"name": "rea-agents", "version": "6.8.0", "file_count": 2398,
                          "tarball_sha256": q.PACKAGE_SHA256, "files_sha256": q.PACKAGE_FILES_SHA256,
                          "catalog_sha256": q.CATALOG_SHA256, "git_source_commit": q.REFERENCE_COMMIT}.items():
        q.require(q.json_equal(reference.get(key), expected), "unfrozen npm identity: " + key)
    q.require(report["node_version"] == "v22.23.4" and q.json_equal(report["native_before"], report["native_after"]),
              "runtime identity changed or is outside the reviewed profile")
    q.require(re.fullmatch(r"[0-9a-f]{64}", report["native_before"]["sha256"]) is not None,
              "native binary digest is absent")
    built = build_binding(root, report, before)
    wires = {label: wire_index(read_artifact(root, report[label + "_wire"])) for label in ("reference", "native")}
    launches = {}
    for label in wires:
        launch = artifact_json(root, report[label + "_launch"])
        launches[label] = launch
        argv = launch["argv"]
        if label == "reference":
            q.require(argv == [report["node_binary"]["path"], str(Path(reference["package_root"]) / "scripts/rea.mjs"), "mcp"],
                      "the frozen original MCP entry point was not used")
            q.require(launch["environment"].get("REA_MCP_INPUT_SCHEMA_PROFILE") == "full"
                      and launch["environment"].get("REA_MCP_OUTPUT_SCHEMA_PROFILE") == "full",
                      "both original schema profiles must be full")
        else:
            q.require(argv[:3] == [report["native_before"]["path"], "mcp", "--runtime-config"]
                      and len(argv) == 4, "the native public MCP entry point was not used")
        close = artifact_json(root, report[label + "_close_artifact"])
        bind_owner(launch, close)
        q.require(q.json_equal(close, report[label + "_close"]) and owner_closed(close)
                  and owner_closed(report[label + "_close"]), "MCP owner needed forced cleanup")
    original_tools = artifact_json(root, report["reference_tools"])
    native_tools = artifact_json(root, report["native_tools"])
    q.require(len(original_tools) == 229, "frozen original MCP inventory size differs")
    bind_tools(wires["reference"], original_tools)
    bind_tools(wires["native"], native_tools)
    if snapshot is not None:
        original = next(item for item in original_tools if item["name"] == "inspect_elf_notes")
        fingerprints = snapshot["schema_fingerprints"]
        q.require(q.digest(original["inputSchema"]) == fingerprints["full_input"]
                  and q.digest(original["outputSchema"]) == fingerprints["full_output"],
                  "wire schemas differ from the independently frozen catalog projection")
    try:
        q.compare_registration(original_tools, native_tools)
        registration = True
    except ValueError:
        registration = False
    comparisons, retained = case_results(cases, report["cases"], root, wires["reference"], wires["native"])
    retention = True
    queries = q.retention_queries(list(retained.values()))
    observed = report["retention_cases"]
    q.require([row["id"] for row in observed] == [query["id"] for query in queries], "retention query set differs")
    for query, row in zip(queries, observed, strict=True):
        left, right = (artifact_json(root, row[label]) for label in ("reference", "native"))
        bind_call(wires["reference"], left, "get_evidence_bundle", query["arguments"])
        bind_call(wires["native"], right, "rea_get_evidence_bundle", query["arguments"])
        try:
            q.require(q.json_equal(q.tool_value(left), q.tool_value(right)), "retention responses differ")
            q.check_retention_response(query, left, list(retained.values()))
        except (KeyError, TypeError, ValueError):
            retention = False
    cold = True
    q.require([row["producer"] for row in report["cold_sessions"]] == ["reference", "native"], "cold sessions are missing")
    for row in report["cold_sessions"]:
        launch = artifact_json(root, row["launch"])
        original = launches[row["producer"]]
        q.require(all(q.json_equal(launch[field], original[field]) for field in ("argv", "cwd", "environment"))
                  and not q.json_equal(launch["owner"], original["owner"]), "cold session is not a new owner under the same profile")
        wire = wire_index(read_artifact(root, row["wire"]))
        value = artifact_json(root, row["response"])
        tool = "get_evidence_bundle" if row["producer"] == "reference" else "rea_get_evidence_bundle"
        bind_call(wire, value, tool, {})
        close = artifact_json(root, row["close_artifact"])
        bind_owner(launch, close)
        q.require(q.json_equal(close, row["close"]), "cold owner close summary differs")
        try:
            q.check_retention_response({"id": "complete", "arguments": {}}, value, [])
            q.require(owner_closed(close) and owner_closed(row["close"]), "cold owner needed forced cleanup")
        except (KeyError, TypeError, ValueError):
            cold = False
    outstanding = [name for name in q.UNIMPLEMENTED_REQUIREMENTS
                   if built is None or name != q.BUILD_REQUIREMENT]
    assessment = derive_assessment(comparisons, registration, retention, cold, outstanding)
    assessment.update({"profile": q.PROFILE, "receipt": receipt_path.relative_to(repo).as_posix(),
                       "receipt_sha256": expected_sha256, "native_binary_sha256": report["native_before"]["sha256"],
                       "source_tree_sha256": before["tree_sha256"], "schema_equal": registration,
                       "retention_equal": retention, "cold_session_empty": cold,
                       "build_source_binding": built})
    return assessment


def consume_index(repo, snapshots, mapping, index_path=INDEX_PATH):
    """No index is exactly the prior inventory-only behavior."""
    path = contained_path(repo, index_path)
    if not path.exists():
        return {}
    index = q.parse_json(path.read_bytes())
    q.require(set(index) == {"schema", "entries"} and index["schema"] == INDEX_SCHEMA,
              "invalid operation qualification index (no handwritten PASS fields)")
    q.require(isinstance(index["entries"], list), "qualification entries are not a list")
    frozen = {row["upstream_tool"]: row for row in snapshots}
    result = {}
    for entry in index["entries"]:
        q.require(set(entry) == {"operation", "profile", "report", "sha256"},
                  "qualification index entries may only reference original receipts")
        operation = entry["operation"]
        q.require(operation == "inspect_elf_notes" and operation in frozen and operation not in result
                  and entry["profile"] == q.PROFILE, "unknown or duplicate operation/profile qualification")
        assessment = validate_report(repo, entry["report"], entry["sha256"], frozen[operation])
        scope = dict(mapping["family_defaults"][frozen[operation]["family"]])
        scope.update(mapping["overrides"].get(operation, {}))
        # A complete implementation declaration is still only a candidate.
        # Finite receipts cannot silently turn partial/related/absent into full.
        if scope["implementation"] != "operation_candidate":
            assessment["status"] = "OPEN"
            assessment["implementation_not_candidate"] = True
        result[operation] = assessment
    return result
