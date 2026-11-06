#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently replay the finite ELF/Evidence v1 receipt without executing MCP.

Raw compressed frames, rows and exports are the facts. Stored PASS, qualified,
comparison and count fields are never authorities. This consumer establishes
only the reviewed Linux finite profile, not complete upstream qualification or
cryptographic attestation against an operator who can replace all inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zlib

import rea_build_evidence as build
import rea_compatibility_ledger as ledger
import rea_elf_evidence_family_qualification as profile
import rea_operation_evidence as operation
import rea_operation_qualification as q
from rea_full_qualification import Selection


SCHEMA = "hepta.rea.elf-evidence-family-assessment.v1"
MAX_SESSION_BYTES = 256 * 1024 * 1024
MAX_FRAMES = 1024
CATALOG_SNAPSHOT = "1997c90ca7c68bbaa89803b2c9b57299df8418b3212a97da0a2c2058e99e2815"
GZIP_FIELDS = {"path", "encoding", "raw_bytes", "raw_sha256", "gzip_bytes", "gzip_sha256"}
SESSION_ORDER = tuple((label, scenario) for label in ("reference", "native")
                      for scenario in profile.EXPECTED_CASES) + (("native", "extension"), ("native", "extension-cold"))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pinned(root, reference, maximum=q.MAX_WIRE_BYTES):
    q.require(isinstance(reference, dict) and set(reference) == {"path", "bytes", "sha256"},
              "artifact must pin only path, bytes and sha256")
    q.require(type(reference["bytes"]) is int and 0 <= reference["bytes"] <= maximum,
              "artifact exceeds the byte allowance")
    raw = build.read_regular(root, reference["path"], reference["bytes"])
    build.check_reference(raw, reference, reference["path"])
    return raw


def json_artifact(root, reference):
    return q.parse_json(read_pinned(root, reference))


def read_gzip(root, reference, maximum=q.MAX_WIRE_BYTES, encoding="gzip-original-bytes"):
    q.require(isinstance(reference, dict) and set(reference) == GZIP_FIELDS
              and reference["encoding"] == encoding, "unknown compressed artifact representation")
    size = reference["raw_bytes"]
    q.require(type(size) is int and 0 <= size <= maximum
              and isinstance(reference["raw_sha256"], str)
              and re.fullmatch(r"[0-9a-f]{64}", reference["raw_sha256"]) is not None,
              "invalid raw artifact size/digest")
    zipped = read_pinned(root, {"path": reference["path"], "bytes": reference["gzip_bytes"],
                              "sha256": reference["gzip_sha256"]}, maximum + 65536)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = decoder.decompress(zipped, size + 1)
    except zlib.error as error:
        raise q.QualificationError("invalid gzip artifact") from error
    q.require(len(raw) == size and decoder.eof and not decoder.unused_data
              and not decoder.unconsumed_tail and sha(raw) == reference["raw_sha256"],
              "gzip is incomplete, exceeds its bound, has trailing members, or differs from its raw digest")
    return raw


def wire_index(root, index_reference):
    raw = read_pinned(root, index_reference)
    q.require(raw.endswith(b"\n"), "unterminated compressed wire index")
    lines = raw.splitlines()
    q.require(1 <= len(lines) <= MAX_FRAMES, "wire frame count outside allowance")
    parent = PurePosixPath(index_reference["path"]).parent
    wire = {"sent": {}, "received": {}, "raw_sent": {}, "raw_received": {}, "entries": {}}
    total, previous, notified = 0, -1, False
    for line in lines:
        entry = q.parse_json(line)
        q.require(isinstance(entry, dict) and set(entry) == GZIP_FIELDS | {"direction", "monotonic_ns"}
                  and entry["direction"] in {"sent", "received"}
                  and type(entry["monotonic_ns"]) is int and entry["monotonic_ns"] >= max(0, previous),
                  "invalid or unordered wire frame")
        previous = entry["monotonic_ns"]
        # The original index uses one basename per frame, never caller paths.
        name = entry["path"]
        q.require(isinstance(name, str) and PurePosixPath(name).name == name
                  and name not in {"", ".", ".."}, "unsafe wire frame basename")
        reference = {key: entry[key] for key in GZIP_FIELDS}
        reference["path"] = (parent / name).as_posix()
        frame = read_gzip(root, reference, encoding="gzip-original-jsonrpc-line")
        total += len(frame)
        q.require(total <= MAX_SESSION_BYTES and frame.endswith(b"\n") and b"\n" not in frame[:-1],
                  "wire session exceeds allowance or frame is not one JSON line")
        value = q.parse_json(frame.decode("utf-8", errors="strict"))
        q.require(isinstance(value, dict) and value.get("jsonrpc") == "2.0", "invalid JSON-RPC frame")
        direction = entry["direction"]
        if "id" not in value:
            q.require(not notified and direction == "sent"
                      and q.json_equal(value, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
                      and any(request["method"] == "initialize" and number in wire["received"]
                              for number, request in wire["sent"].items()),
                      "unexpected or premature notification in family wire")
            notified = True
            continue
        identifier = value["id"]
        q.require(type(identifier) is int and identifier > 0 and identifier not in wire[direction],
                  "invalid or duplicate wire request/response ID")
        if direction == "sent":
            q.require(value.get("method") in {"initialize", "tools/list", "tools/call"},
                      "unexpected client request in family profile")
            q.require(set(wire["sent"]) == set(wire["received"]),
                      "family requests must complete before the next request begins")
            q.require((value["method"] == "initialize" and not wire["sent"] and not notified)
                      or (value["method"] != "initialize" and notified),
                      "family request precedes initialization or repeats its handshake")
        else:
            q.require(identifier in wire["sent"] and "method" not in value
                      and (("result" in value) != ("error" in value)),
                      "wire response has no prior request or has an invalid result/error envelope")
        wire[direction][identifier] = value
        wire["raw_" + direction][identifier] = frame
        wire["entries"][(direction, identifier)] = {**entry, "path": reference["path"]}
    q.require(set(wire["sent"]) == set(wire["received"]), "wire requests are incomplete")
    wire["first_ns"] = q.parse_json(lines[0])["monotonic_ns"]
    wire["last_ns"] = previous
    wire["initialized_notification"] = notified
    return wire


class ReplaySession:
    """Consume every original call once, in the independently requested sequence."""

    def __init__(self, root, label, scenario, state, report, workspace):
        self.root, self.label, self.scenario = Path(root), label, scenario
        self.state, self.position, self.exports = state, 0, {}
        prefix = label + "-" + scenario
        for field, filename in (("wire_index", "wire.jsonl"), ("launch", "launch.json"),
                                ("close_artifact", "close.json"), ("stderr", "stderr.log"),
                                ("initialize", "initialize.json"), ("tools", "tools.json")):
            q.require(state[field]["path"] == prefix + "/" + filename, "session artifact path was substituted")
        self.wire = wire_index(root, state["wire_index"])
        self.launch = json_artifact(root, state["launch"])
        self.close = json_artifact(root, state["close_artifact"])
        read_pinned(root, state["stderr"])
        operation.bind_owner(self.launch, self.close)
        q.require(q.json_equal(self.close, state["close"]) and operation.owner_closed(self.close),
                  "owner close differs, needed forced cleanup, or failed to drain")
        expected = ([report["node_before"]["path"], str(Path(report["reference_before"]["package_root"]) / "scripts/rea.mjs"), "mcp"]
                    if label == "reference" else [report["binary_before"]["path"], "mcp", "--runtime-config", str(workspace.parent / "runtime.json")])
        environment = ({"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full",
                        "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"} if label == "reference" else {})
        q.require(q.json_equal(self.launch["argv"], expected) and self.launch["cwd"] == str(workspace)
                  and q.json_equal(self.launch["environment"], environment), "MCP launch input differs from reviewed profile")
        initializes = [number for number, row in self.wire["sent"].items() if row["method"] == "initialize"]
        q.require(initializes == [1] and self.wire["initialized_notification"]
                  and "result" in self.wire["received"][1]
                  and q.json_equal(self.wire["sent"][1], {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                      "protocolVersion": "2026-07-28", "capabilities": {},
                      "clientInfo": {"name": "hepta-rea-operation-qualification", "version": "1"}}})
                  and q.json_equal(json_artifact(root, state["initialize"]),
                                                       self.wire["received"][initializes[0]]), "initialize is not bound to its wire")
        self.tools = json_artifact(root, state["tools"])
        operation.bind_tools(self.wire, self.tools)
        by_name = {row["name"]: row for row in self.tools}
        q.require(len(by_name) == len(self.tools), "duplicate advertised tool")
        self.contracts = {}
        for name, alias in profile.ALIASES.items():
            key = alias if label == "native" else name
            q.require(key in by_name, "missing public family route")
            self.contracts[name] = {field: by_name[key].get(field) for field in ("inputSchema", "outputSchema", "annotations")}
        q.require(q.json_equal(self.contracts, state["contracts"]), "contract summary differs from tools/list")
        if scenario.startswith("extension"):
            wanted = {name: by_name[name] for name in profile.EXTENSIONS.values()}
            q.require(q.json_equal(wanted, state["extension_contracts"]), "extension schemas differ from tools/list")
        self.rows = []
        seen = set()
        for metadata in state["rows"]:
            q.require(set(metadata) == {"id", "operation", "artifact", "request_wire", "response_wire"}, "unknown case reference fields")
            row = q.parse_json(read_gzip(root, metadata["artifact"]))
            q.require(set(row) == {"id", "operation", "arguments", "response", "response_bytes", "response_sha256", "seconds"}
                      and row["id"] == metadata["id"] and row["operation"] == metadata["operation"], "case artifact metadata differs")
            identifier = row["response"].get("id")
            q.require(type(identifier) is int and identifier not in seen, "duplicate case response ID")
            seen.add(identifier)
            for direction, field in (("sent", "request_wire"), ("received", "response_wire")):
                q.require(q.json_equal(metadata[field], self.wire["entries"].get((direction, identifier))),
                          "case selected a frame absent from the complete original index")
            alias = (profile.EXTENSIONS.get(row["operation"], profile.ALIASES.get(row["operation"]))
                     if label == "native" else row["operation"])
            operation.bind_call(self.wire, row["response"], alias, row["arguments"])
            frame = self.wire["raw_received"][identifier]
            q.require(type(row["response_bytes"]) is int and row["response_bytes"] == len(frame)
                      and row["response_sha256"] == sha(frame), "case response frame digest/length differs")
            self.rows.append({**row, "response": self.wire["received"][identifier]})
        call_ids = {number for number, row in self.wire["sent"].items() if row["method"] == "tools/call"}
        q.require(seen == call_ids, "case rows omit or invent original wire calls")
        q.require([row["response"]["id"] for row in self.rows]
                  == [number for number, request in self.wire["sent"].items() if request["method"] == "tools/call"],
                  "case order differs from the original wire order")

    def call(self, name, operation_name, arguments):
        q.require(self.position < len(self.rows), "missing required family call: " + name)
        row = self.rows[self.position]
        q.require(row["id"] == name and row["operation"] == operation_name
                  and q.json_equal(row["arguments"], arguments), "required case sequence/input differs: " + name)
        self.position += 1
        q.tool_value(row["response"])
        return row["response"]

    def export(self, name, path, expected=None, expected_raw=None):
        response = self.call(name, "export_evidence_bundle", {"path": str(path), "overwrite": True})
        entry = self.state["exports"][name]
        raw = read_gzip(self.root, entry["artifact"], profile.MAX_EXPORT_BYTES)
        q.require(q.json_equal(entry["file"], {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}),
                  "export file identity differs from retained complete bytes")
        bundle = profile.validate_bundle(q.parse_json(raw), expected)
        q.require(q.json_equal(profile.payload(response, target=False)["result"],
                              {"path": str(path), "bytes": len(raw), "records": len(bundle["records"]), "unknowns": 0}),
                  "export wire result differs from complete retained bytes")
        q.require(raw == profile.canonical_json(bundle) and (expected_raw is None or raw == expected_raw),
                  "export bytes differ from exact canonical expected bundle")
        self.exports[name] = raw
        return raw, bundle

    def finish(self):
        q.require(self.position == len(self.rows) and set(self.exports) == set(self.state["exports"]),
                  "unconsumed or invented calls/exports remain")


def small_facts(fixture):
    return {**fixture, "entries": 1, "tables": 1, "owner": "GNU", "format": "elf64",
            "byte_order": "little", "descriptor_hex": bytes(range(20)).hex()}


def verify_producer(session, fixtures, workspace):
    profile.complete(session.call("empty", "get_evidence_bundle", {}), [])
    real_args = {"path": fixtures["real"]["path"], "max_entries": 256}
    real = q.evidence_value(session.call("real-elf", "inspect_elf_notes", real_args))
    profile.check_real_record(real, fixtures["real"])
    repeated = q.evidence_value(session.call("real-repeat", "inspect_elf_notes", real_args))
    q.require(q.json_equal(real, repeated), "same real input changed its complete Evidence")
    small_args = {"path": fixtures["small"]["path"]}
    small = q.evidence_value(session.call("controlled-elf", "inspect_elf_notes", small_args))
    q.check_independent_facts(small, {"arguments": small_args, "facts": small_facts(fixtures["small"])})
    records = [real, small]
    profile.complete(session.call("small-complete", "get_evidence_bundle", {}), records)
    for name in ("small-summary", "small-summary-repeat"):
        profile.summary(session.call(name, "get_evidence_bundle", {"detail": "summary"}), records)
    filters = {"evidence_id": real["evidence_id"]}
    profile.summary(session.call("small-filtered-summary", "get_evidence_bundle", {"detail": "summary", "filters": filters}), records, filters)
    for name, arguments in (("corrupt-elf", {"path": fixtures["corrupt"]["path"]}),
                            ("file-budget", {**small_args, "max_file_bytes": 64}),
                            ("entry-budget", {"path": fixtures["two-notes"]["path"], "max_entries": 1}),
                            ("missing-elf", {"path": str(workspace / "absent.elf")}),
                            ("invalid-limit", {**small_args, "max_entries": False})):
        profile.public_error(session.call(name, "inspect_elf_notes", arguments))
    profile.complete(session.call("failed-inputs-unchanged", "get_evidence_bundle", {}), records)
    session.export("export-small", workspace / "small.json", records)
    limits = profile.overflow(session.call("body-overflow", "inspect_elf_notes", {"path": fixtures["overflow"]["path"]}), "inspect_elf_notes")
    parent_id = limits["evidence_id"]
    q.require(isinstance(parent_id, str) and re.fullmatch(r"ev_[0-9a-f]{64}", parent_id) is not None
              and q.json_equal(limits["evidence_reference"], {"kind": "retained-evidence", "evidence_id": parent_id}),
              "overflow lost its retained Evidence reference")
    overflow_summary = session.call("overflow-summary", "get_evidence_bundle", {"detail": "summary"})
    profile.overflow(session.call("bundle-overflow", "get_evidence_bundle", {}), "get_evidence_bundle")
    profile.unsupported_elf_view(session.call("elf-view-unsupported", "inspect_analysis_view", {
        "source": {"kind": "retained-evidence", "evidence_id": parent_id}, "view": {"kind": "summary"}}))
    raw, bundle = session.export("export-full", workspace / "full.json")
    parent = next((record for record in bundle["records"] if record["evidence_id"] == parent_id), None)
    q.require(parent is not None, "overflow export omitted its referenced complete record")
    profile.check_overflow_record(parent, fixtures["overflow"])
    profile.validate_bundle(bundle, records + [parent])
    profile.summary(overflow_summary, bundle["records"])
    profile.summary(session.call("post-export-summary", "get_evidence_bundle", {"detail": "summary"}), bundle["records"])
    session.finish()
    return raw, bundle, parent_id


def verify_restore(session, workspace, raw, bundle, parent_id):
    records = bundle["records"]
    profile.complete(session.call("empty", "get_evidence_bundle", {}), [])
    if session.scenario == "cold":
        profile.counts(session.call("import-restored", "import_evidence_bundle", {"path": str(workspace / "restored.json")}), 3, 3)
        profile.summary(session.call("summary", "get_evidence_bundle", {"detail": "summary"}), records)
        session.export("export-cold", workspace / "cold.json", records, raw)
    else:
        arguments = {"path": str(workspace / "original-source.json")}
        profile.counts(session.call("import-full", "import_evidence_bundle", arguments), 3, 3)
        profile.summary(session.call("summary", "get_evidence_bundle", {"detail": "summary"}), records)
        profile.counts(session.call("import-repeat", "import_evidence_bundle", arguments), 0, 3)
        profile.summary(session.call("summary-repeat", "get_evidence_bundle", {"detail": "summary"}), records)
        profile.overflow(session.call("bundle-overflow", "get_evidence_bundle", {}), "get_evidence_bundle")
        profile.unsupported_elf_view(session.call("elf-view-unsupported", "inspect_analysis_view", {
            "source": {"kind": "retained-evidence", "evidence_id": parent_id}, "view": {"kind": "summary"}}))
        session.export("export-restored", workspace / "restored.json", records, raw)
        for name in ("truncated", "tampered", "missing"):
            filename = "absent-source.json" if name == "missing" else name + "-source.json"
            failure = profile.public_error(session.call("import-" + name, "import_evidence_bundle", {"path": str(workspace / filename)}))
            if name != "missing":
                q.require(failure["code"] == "evidence_integrity_mismatch", "invalid import was not refused for integrity")
            session.export("after-" + name, workspace / "restored.json", records, raw)
        profile.summary(session.call("final-summary", "get_evidence_bundle", {"detail": "summary"}), records)
    session.finish()


def verify_extension(session, fixtures, workspace, original_raw, original_bundle):
    profile.complete(session.call("empty", "get_evidence_bundle", {}), [])
    profile.counts(session.call("import-full", "import_evidence_bundle", {"path": str(workspace / "original-source.json")}), 3, 3)
    first = profile.readback_page(session.call("freeze-original", "read_evidence_bundle", {}), original_raw, 3, 0, 65536)
    old_id = first["snapshot_id"]
    arguments = {"path": fixtures["unicode"]["path"], "max_entries": 31}
    grown = q.evidence_value(session.call("new-observation", "inspect_elf_notes", arguments))
    q.check_independent_facts(grown, {"arguments": arguments, "facts": small_facts(fixtures["unicode"])})
    q.require(grown["evidence_id"] not in {row["evidence_id"] for row in original_bundle["records"]}, "new observation did not add a record")
    records = original_bundle["records"] + [grown]
    expanded, _ = session.export("export-expanded", workspace / "expanded.json", records)
    q.require(expanded != original_raw, "live bundle did not change")
    replay = profile.readback_page(session.call("replay-before-continuation", "read_evidence_bundle", {
        "snapshot_id": old_id, "offset": 0, "length": 65536}), original_raw, 3, 0, 65536, old_id)
    q.require(q.json_equal(first, replay), "old snapshot changed after an actual new observation")
    for name, arguments in (("missing-cursor", {"offset": 1, "length": 1}),
                            ("zero-length", {"snapshot_id": old_id, "offset": 0, "length": 0}),
                            ("excessive-length", {"snapshot_id": old_id, "offset": 0, "length": 262145}),
                            ("out-of-range", {"snapshot_id": old_id, "offset": len(original_raw) + 1, "length": 1}),
                            ("unknown-cursor", {"snapshot_id": "ebs1_" + "0" * 64, "offset": 0, "length": 1}),
                            ("malformed-cursor", {"snapshot_id": "ebs1_invalid", "offset": 0, "length": 1})):
        profile.public_error(session.call(name, "read_evidence_bundle", arguments))
    restored, page, pages = bytearray(bytes.fromhex(first["bytes_hex"])), first, 1
    while not page["eof"]:
        q.require(pages < 65 and page["next_offset"] == len(restored), "nonprogressing continuation")
        offset = page["next_offset"]
        page = profile.readback_page(session.call(f"continuation-{pages:02d}", "read_evidence_bundle", {
            "snapshot_id": old_id, "offset": offset, "length": 262144}), original_raw, 3, offset, 262144, old_id)
        restored.extend(bytes.fromhex(page["bytes_hex"]))
        pages += 1
    q.require(bytes(restored) == original_raw and pages > 1, "continuation did not recover the complete export")
    profile.readback_page(session.call("exact-eof", "read_evidence_bundle", {
        "snapshot_id": old_id, "offset": len(original_raw), "length": 1}), original_raw, 3, len(original_raw), 1, old_id)
    fresh = profile.readback_page(session.call("freeze-current", "read_evidence_bundle", {}), expanded, 4, 0, 65536)
    new_id = fresh["snapshot_id"]
    q.require(old_id != new_id, "new bundle reused the previous content identity")
    offset = max(0, len(expanded) - 137)
    profile.readback_page(session.call("current-tail", "read_evidence_bundle", {
        "snapshot_id": new_id, "offset": offset, "length": 137}), expanded, 4, offset, 137, new_id)
    offset = expanded.index("中".encode()) + 1
    profile.readback_page(session.call("inside-utf8-codepoint", "read_evidence_bundle", {
        "snapshot_id": new_id, "offset": offset, "length": 1}), expanded, 4, offset, 1, new_id)
    profile.snapshot_release(session.call("release-original", "close_evidence_snapshot", {"snapshot_id": old_id}),
                             old_id, True, len(original_raw), 1, len(expanded))
    profile.public_error(session.call("released-cursor", "read_evidence_bundle", {"snapshot_id": old_id, "length": 1}))
    profile.snapshot_release(session.call("release-original-repeat", "close_evidence_snapshot", {"snapshot_id": old_id}),
                             old_id, False, 0, 1, len(expanded))
    session.export("release-preserves-evidence", workspace / "expanded.json", records, expanded)
    session.finish()
    return {"old_snapshot_id": old_id, "snapshot_id": new_id, "pages": pages,
            "reconstructed_bytes": len(restored), "reconstructed_sha256": sha(restored)}


def verify_extension_cold(session, workspace, raw, bundle, previous):
    profile.complete(session.call("empty", "get_evidence_bundle", {}), [])
    for suffix, token in (("live", previous["snapshot_id"]), ("released", previous["old_snapshot_id"])):
        profile.public_error(session.call("foreign-" + suffix, "read_evidence_bundle", {"snapshot_id": token, "length": 1}))
    profile.counts(session.call("import-full", "import_evidence_bundle", {"path": str(workspace / "original-source.json")}), 3, 3)
    profile.public_error(session.call("import-does-not-restore-cursor", "read_evidence_bundle", {
        "snapshot_id": previous["old_snapshot_id"], "length": 1}))
    fresh = profile.readback_page(session.call("explicit-fresh-snapshot", "read_evidence_bundle", {"length": 7}), raw, 3, 0, 7)
    profile.snapshot_release(session.call("release-fresh", "close_evidence_snapshot", {"snapshot_id": fresh["snapshot_id"]}),
                             fresh["snapshot_id"], True, len(raw), 0, 0)
    profile.public_error(session.call("released-fresh-cursor", "read_evidence_bundle", {"snapshot_id": fresh["snapshot_id"], "length": 1}))
    session.export("unchanged-after-release", workspace / "extension-cold.json", bundle["records"], raw)
    session.finish()


def verify_fixtures(root, report):
    fixtures = json_artifact(root, report["fixtures"])
    q.require(set(fixtures) == {"real", "small", "unicode", "overflow", "corrupt", "two-notes"},
              "reviewed fixture set differs")
    workspace = Path(build.absolute_name(fixtures["real"]["path"])).parent
    known = {"small": q.elf(q.note()), "unicode": q.elf(q.note()), "overflow": profile.oversized_elf(),
             "corrupt": q.elf(q.note())[:-1], "two-notes": q.elf(q.note() + q.note())}
    for name, reference in fixtures.items():
        filename = "unicode-中文-🙂.elf" if name == "unicode" else name + ".elf"
        raw = build.read_regular(root, "workspace/" + filename, profile.MAX_INPUT_BYTES)
        expected = {"path": str(workspace / filename), "bytes": len(raw), "sha256": sha(raw)}
        q.require(q.json_equal(reference, expected), "fixture identity differs from archived bytes: " + name)
        if name == "real":
            identity = report["real_input_before"]
            q.require(len(raw) >= 64 and raw.startswith(b"\x7fELF")
                      and q.json_equal(identity["bytes"], len(raw)) and identity["sha256"] == sha(raw),
                      "real ELF is not bound to the archived input")
        else:
            q.require(raw == known[name], "independent authored fixture bytes changed: " + name)
    config = q.parse_json(build.read_regular(root, "runtime.json", q.MAX_WIRE_BYTES))
    expected = {"controller_workspace_roots": [str(workspace)], "state_dir": str(workspace.parent / "state"),
                "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(workspace.parent / "unused-remote"),
                    "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
    q.require(q.json_equal(config, expected), "native runtime configuration differs from the reviewed local profile")
    return fixtures, workspace


def verify_shared_imports(root, report, workspace, raw, bundle):
    changed = q.parse_json(raw)
    changed["records"][-1]["normalized_result"]["artifact"]["bytes"] += 1
    q.require(changed["records"][-1]["evidence_id"] != q.semantic_evidence_id(changed["records"][-1]),
              "tampered input did not invalidate the retained Evidence identity")
    expected = {"original-source.json": raw, "truncated-source.json": raw[:-1],
                "tampered-source.json": profile.canonical_json(changed)}
    references = json_artifact(root, report["shared_import_inputs"])
    q.require(set(references) == set(expected), "shared import source set differs")
    for name, body in expected.items():
        actual = build.read_regular(root, "workspace/" + name, profile.MAX_EXPORT_BYTES)
        q.require(actual == body and q.json_equal(references[name], {
            "path": str(workspace / name), "bytes": len(body), "sha256": sha(body)}),
            "shared differential import bytes/identity differ: " + name)


def verify_identity_and_source(repo, root, report):
    for name in ("binary", "node", "real_input"):
        before = report[name + "_before"]
        q.require(isinstance(before, dict) and set(before) == {"path", "bytes", "sha256"}
                  and type(before["bytes"]) is int and before["bytes"] > 0
                  and isinstance(before["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", before["sha256"]) is not None
                  and q.json_equal(before, report[name + "_after"]), "selected input identity changed: " + name)
        build.absolute_name(before["path"])
    q.require(report["node_version"] == "v22.23.4" and report["node_before"]["sha256"] == profile.NODE_SHA256,
              "unfrozen Node executable/version")
    reference = report["reference_before"]
    q.require(q.json_equal(reference, report["reference_after"]), "original npm package changed")
    for key, value in {"name": "rea-agents", "version": "6.8.0", "file_count": 2398,
                       "tarball_sha256": q.PACKAGE_SHA256, "files_sha256": q.PACKAGE_FILES_SHA256,
                       "catalog_sha256": q.CATALOG_SHA256, "git_source_commit": q.REFERENCE_COMMIT}.items():
        q.require(q.json_equal(reference.get(key), value), "unfrozen original npm identity: " + key)
    build.absolute_name(reference["package_root"])
    before = json_artifact(root, report["source_before"])
    after = json_artifact(root, report["source_after"])
    events = json_artifact(root, report["source_events"])
    q.require(q.json_equal(before, after) and before["tree_sha256"] == q.digest(before["files"]),
              "selected source inventory changed or its digest differs")
    q.require(type(events["event_count"]) is int and events["event_count"] == 0
              and events["retained_events"] == [] and events["events_truncated"] is False and events["errors"] == [],
              "source monitor reported a change or lost coverage")
    current = Selection(Path(repo), Path(root) / "unused-target", Path(root)).snapshot()
    q.require(q.json_equal(before, current), "receipt belongs to a different selected source tree")
    bundle = report.get("build_evidence")
    binding = None if bundle is None else build.validate_bundle(root, bundle, before, report["binary_before"])
    return before, binding


def verify_frozen_contracts(repo, sessions):
    stored = ledger.read_json(Path(repo) / ledger.LEDGER_PATH)
    rows = ledger.snapshot_rows(stored["tools"])
    q.require(ledger.digest_json(rows) == CATALOG_SNAPSHOT, "frozen catalog projection differs")
    by_name = {row["upstream_tool"]: row for row in rows}
    for session in sessions:
        if session.label != "reference":
            continue
        advertised = {row["name"]: row for row in session.tools}
        q.require(len(advertised) == 229, "frozen original tool inventory count differs")
        for name in profile.ALIASES:
            fingerprints = by_name[name]["schema_fingerprints"]
            q.require(q.digest(advertised[name]["inputSchema"]) == fingerprints["full_input"]
                      and q.digest(advertised[name]["outputSchema"]) == fingerprints["full_output"]
                      and q.json_equal(advertised[name].get("annotations", {}), by_name[name]["upstream_annotations"]),
                      "original wire schema differs from frozen catalog: " + name)


def verify_owner_set(sessions):
    owners = set()
    previous = -1
    for key in SESSION_ORDER:
        session = sessions[key]
        owner = session.close["owner"]
        identity = (owner["pid"], owner["start_time_ticks"])
        q.require(identity not in owners, "an owner observation was reused for a fresh session")
        owners.add(identity)
        q.require(session.wire["first_ns"] > previous, "session wire intervals overlap or are out of order")
        previous = session.wire["last_ns"]
    return len(owners)


def validate_report(repo, receipt_path, expected_sha256):
    repo, receipt_path = Path(repo), Path(receipt_path)
    q.require(repo.is_absolute() and receipt_path.is_absolute(), "repo and receipt paths must be absolute")
    root = receipt_path.parent
    raw = build.read_regular(root, receipt_path.name, q.MAX_WIRE_BYTES)
    q.require(sha(raw) == expected_sha256, "family receipt digest differs")
    report = q.parse_json(raw)
    q.require(report["schema"] == profile.SCHEMA and report["profile"] == profile.PROFILE,
              "unknown family qualification profile")
    source, binding = verify_identity_and_source(repo, root, report)
    fixtures, workspace = verify_fixtures(root, report)
    expected_sessions = {label + "/" + scenario for label, scenario in SESSION_ORDER}
    q.require(set(report["sessions"]) == expected_sessions, "required eight-session set differs")
    sessions = {key: ReplaySession(root, *key, report["sessions"][key[0] + "/" + key[1]], report, workspace)
                for key in SESSION_ORDER}
    verify_frozen_contracts(repo, sessions.values())
    owners = verify_owner_set(sessions)
    original_raw = original_bundle = parent_id = None
    for label in ("reference", "native"):
        raw_bundle, bundle, observed_parent = verify_producer(sessions[(label, "producer")], fixtures, workspace)
        if label == "reference":
            original_raw, original_bundle, parent_id = raw_bundle, bundle, observed_parent
            verify_shared_imports(root, report, workspace, original_raw, original_bundle)
        for scenario in ("restore", "cold"):
            verify_restore(sessions[(label, scenario)], workspace, original_raw, original_bundle, parent_id)
    extension = verify_extension(sessions[("native", "extension")], fixtures, workspace, original_raw, original_bundle)
    verify_extension_cold(sessions[("native", "extension-cold")], workspace, original_raw, original_bundle, extension)
    comparisons = []
    for scenario, expected in profile.EXPECTED_CASES.items():
        left, right = (sessions[(label, scenario)] for label in ("reference", "native"))
        q.require(tuple(row["id"] for row in left.rows) == expected
                  and tuple(row["id"] for row in right.rows) == expected, "public case set differs")
        for first, second in zip(left.rows, right.rows, strict=True):
            comparisons.append({**profile.compare_row(first, second), "id": scenario + "/" + first["id"]})
        same = q.json_equal(left.contracts, right.contracts)
        comparisons.append({"id": scenario + "/contracts", "status": "PASS" if same else "FAIL"})
        q.require(set(left.exports) == set(right.exports), "export comparison set differs")
        for name in left.exports:
            same = left.exports[name] == right.exports[name]
            comparisons.append({"id": scenario + "/" + name + "-canonical-bytes", "status": "PASS" if same else "FAIL"})
    q.require(len(comparisons) == 50 and owners == 8, "finite observation coverage differs")
    complete = all(row["status"] == "PASS" for row in comparisons)
    outstanding = [name for name in profile.OPEN_REQUIREMENTS if name != "independent-operation-receipt-consumer"
                   and (binding is None or name != "full-final-combination-build-source-attestation")]
    return {"schema": SCHEMA, "profile": profile.PROFILE, "status": "OPEN" if complete else "FAILED",
            "finite_status": "PASS" if complete else "FAIL", "qualified": False,
            "scope": "finite Linux ELF/Evidence family v1 only; no upstream operation-ledger promotion",
            "receipt_sha256": expected_sha256, "source_tree_sha256": source["tree_sha256"],
            "native_binary_sha256": report["binary_before"]["sha256"], "build_source_binding": binding,
            "comparisons": comparisons, "normal_owner_closes": owners, "native_readback": extension,
            "open_requirements": outstanding}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_report(args.repo, args.report, args.sha256)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "INVALID", "qualified": False,
                          "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

