#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run the frozen ELF/Evidence public family through actual original and Rust MCPs.

A pinned real ELF and an independently encoded oversized ELF are both inspected.
The oversized result must remain complete after the unchanged 10 MiB response
boundary, public export, owner EOF, explicit import in a new process, rejected
imports, and a second export/import cycle. Complete CallToolResult objects keep
content.text opaque in the differential; original JSON-RPC lines are retained.

REA 6.8.0 rejects ELF analysis views. This profile checks that rejection and uses
the original export route for complete readback. Native-only immutable byte
snapshots are exercised separately, without an upstream parity claim. Active
ELF cancellation, deadlines, the complete format corpus and an independent
qualification consumer remain separate requirements.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import rea_operation_qualification as q
from rea_frame_mcp_qualification import CompressedMcp
from rea_full_qualification import Selection, SourceMonitor


SCHEMA = "hepta.rea.elf-evidence-family.v1"
PROFILE = "rea-agents-6.8.0/elf-evidence-family/v1"
NODE_SHA256 = "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
DESCRIPTOR_BYTES = 3 * 1024 * 1024
OVERSIZED_SHA256 = "1e53cc76b48d0e323008129bb1fa497866e612d399659802c987ebda22217c9b"
DESCRIPTOR_SHA256 = "f6dd7fec8584ad00219a447071c1fa368a1caee4d9c146083d233713ddccd2c0"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_EXPORT_BYTES = 16 * 1024 * 1024
BUNDLE_KEYS = {"artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records"}
ALIASES = {"inspect_elf_notes": "rea_inspect_elf_notes",
           "get_evidence_bundle": "rea_get_evidence_bundle",
           "export_evidence_bundle": "rea_export_evidence_bundle",
           "import_evidence_bundle": "rea_import_evidence_bundle",
           "inspect_analysis_view": "rea_inspect_analysis_view"}
EXTENSIONS = {"read_evidence_bundle": "rea_read_evidence_bundle",
              "close_evidence_snapshot": "rea_close_evidence_snapshot"}
READBACK_PROFILE = "hepta.evidence-bundle-readback.v1"
EXPECTED_CASES = {
    "producer": ("empty", "real-elf", "real-repeat", "controlled-elf", "small-complete",
                 "small-summary", "small-summary-repeat", "small-filtered-summary",
                 "corrupt-elf", "file-budget", "entry-budget", "missing-elf", "invalid-limit",
                 "failed-inputs-unchanged", "export-small", "body-overflow", "overflow-summary",
                 "bundle-overflow", "elf-view-unsupported", "export-full", "post-export-summary"),
    "restore": ("empty", "import-full", "summary", "import-repeat", "summary-repeat",
                "bundle-overflow", "elf-view-unsupported", "export-restored", "import-truncated",
                "after-truncated", "import-tampered", "after-tampered", "import-missing",
                "after-missing", "final-summary"),
    "cold": ("empty", "import-restored", "summary", "export-cold"),
}
OPEN_REQUIREMENTS = (
    "active-elf-cancellation-and-owner-drain", "elf-worker-deadline-and-owner-drain",
    "complete-format-overflow-and-compressed-name-corpus",
    "full-final-combination-build-source-attestation", "independent-operation-receipt-consumer",
    "all-native-readback-capacity-cancellation-and-provider-profiles",
    "cross-platform-and-multihost-qualification", "complete-cost-and-concurrent-fault-qualification",
)


def stamp(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink)


def read_stable(path, maximum):
    """Capture one bounded, non-linked regular file without a FIFO-open race."""
    path = Path(path)
    before = path.lstat()
    q.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and 0 <= before.st_size <= maximum, "file is linked, nonregular or oversized: " + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        q.require(stamp(os.fstat(stream.fileno())) == stamp(before), "file changed before capture")
        raw = stream.read(maximum + 1)
        q.require(stamp(os.fstat(stream.fileno())) == stamp(before), "file changed during capture")
    q.require(stamp(path.lstat()) == stamp(before) and len(raw) == before.st_size,
              "file changed while capturing: " + str(path))
    return raw, {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_new(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return q.identity(path)


def archive_raw(root, path, raw):
    with path.open("xb") as target:
        with gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as stream:
            stream.write(raw)
    return {"path": path.relative_to(root).as_posix(), "encoding": "gzip-original-bytes",
            "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "gzip_bytes": path.stat().st_size, "gzip_sha256": q.file_hash(path)}


def oversized_elf():
    """A 3 MiB GNU descriptor plus unreferenced padding admits its 6 MiB hex text."""
    descriptor = bytes(range(256)) * (DESCRIPTOR_BYTES // 256)
    raw = q.elf(q.note(descriptor=descriptor)) + bytes(DESCRIPTOR_BYTES)
    q.require(hashlib.sha256(raw).hexdigest() == OVERSIZED_SHA256
              and hashlib.sha256(descriptor).hexdigest() == DESCRIPTOR_SHA256,
              "independent oversized ELF bytes changed")
    return raw


def canonical_json(value):
    # All records in this profile must pass q.semantic_evidence_id's explicitly
    # limited integer-only verifier before this exact export comparison is used.
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def payload(response, target=True):
    value = q.tool_value(response)
    q.require("rpc_error" not in value and value.get("isError", False) is False
              and "structuredContent" in value, "expected a complete successful public result")
    if target:
        q.require(q.json_equal(value.get("_meta"), q.TARGET_META), "target provenance is missing")
    else:
        q.require("_meta" not in value, "target-free export unexpectedly carries target metadata")
    return value["structuredContent"]


def public_error(response):
    value = q.tool_value(response)
    q.require("rpc_error" not in value and value.get("isError") is True,
              "expected a public tool failure, not an RPC or connection failure")
    body = value["content"][0]["text"]
    q.require(isinstance(body, dict) and isinstance(body.get("error"), dict), "tool failure body is missing")
    return body["error"]


def overflow(response, operation):
    failure = public_error(response)
    details = failure["details"]
    limits = details["reported_limits"]
    q.require(failure["code"] == "resource_constraint" and failure["retryable"] is False
              and details["operation"] == operation and details["resource"] == "transport"
              and limits["boundary"] == "mcp-response"
              and limits["default_receive_buffer_bytes"] == 10 * 1024 * 1024
              and limits["result_budget_bytes"] == 10 * 1024 * 1024 - 1024
              and limits["constraint"] == "receive-buffer"
              and type(limits["response_bytes_at_least"]) is int
              and limits["response_bytes_at_least"] > limits["result_budget_bytes"],
              "operation did not complete at the unchanged body response boundary")
    return limits


def validate_bundle(bundle, expected=None):
    q.require(isinstance(bundle, dict) and set(bundle) == BUNDLE_KEYS
              and all(isinstance(bundle[key], list) for key in BUNDLE_KEYS), "bundle manifests differ")
    records = bundle["records"]
    q.require([r["evidence_id"] for r in records] == sorted({r["evidence_id"] for r in records}),
              "complete records are not unique and deterministically ordered")
    for record in records:
        q.require(record["operation"] == "inspect_elf_notes"
                  and q.json_equal(record["provider"], q.PROVIDER)
                  and record["evidence_id"] == q.semantic_evidence_id(record),
                  "retained ELF Evidence identity/provider differs")
    q.require(all(bundle[key] == [] for key in ("unknowns", "environments", "scenarios", "captures")),
              "notes-only session contains unrelated manifests")
    q.require(q.json_equal(bundle["providers"], [q.PROVIDER] if records else []), "provider manifest differs")
    artifacts = {}
    for record in records:
        subject = record["subject"]
        item = {key: subject[key] for key in ("digest", "format", "architecture")}
        key = json.dumps(item, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        artifacts[key] = item
    q.require(q.json_equal(bundle["artifacts"], [artifacts[key] for key in sorted(artifacts)]),
              "artifact manifest is incomplete or misordered")
    if expected is not None:
        q.require(q.json_equal(records, sorted(expected, key=lambda r: r["evidence_id"])),
                  "complete retained records changed")
    return bundle


def complete(response, expected):
    return validate_bundle(payload(response)["result"], expected)


def summary(response, expected, filters=None):
    arguments = {"detail": "summary"}
    if filters is not None:
        arguments["filters"] = filters
    q.check_retention_response({"id": "summary", "arguments": arguments}, response, expected)
    return payload(response)["result"]


def counts(response, imported, total):
    q.require(q.json_equal(payload(response)["result"],
                          {"imported": imported, "unknowns_added": 0, "total": total}),
              "public import counts disagree with the selected complete bundle")


def unsupported_elf_view(response):
    failure = public_error(response)
    q.require(failure["code"] == "unsupported_target"
              and failure["details"]["operation"] == "inspect_analysis_view"
              and "inspect_elf_notes" in failure["details"]["reason"],
              "frozen ELF analysis-view rejection changed")


def closed_normally(observation):
    return (type(observation.get("returncode")) is int and observation["returncode"] == 0
            and observation.get("forced_cleanup") == [] and observation.get("reader_stopped") is True
            and observation.get("owner_pidfd_exited") is True and observation.get("process_group_gone") is True)


class Session:
    def __init__(self, label, scenario, command, environment, workspace, output, root, report):
        self.label, self.scenario, self.output, self.root = label, scenario, output, root
        self.rows = []
        self.state = {"rows": [], "exports": {}}
        report["sessions"][label + "/" + scenario] = self.state
        self.client = CompressedMcp(command, workspace, environment, output)

    def initialize(self):
        self.state["initialize"] = q.artifact_json(
            self.root, str(self.output.relative_to(self.root) / "initialize.json"), self.client.initialize())
        tools = self.client.tools()
        selected = {}
        by_name = {tool["name"]: tool for tool in tools}
        for operation, alias in ALIASES.items():
            name = alias if self.label == "native" else operation
            q.require(name in by_name, "public tool is missing: " + name)
            selected[operation] = {key: by_name[name].get(key)
                                   for key in ("inputSchema", "outputSchema", "annotations")}
        self.state["contracts"] = selected
        if self.scenario.startswith("extension"):
            q.require(self.label == "native" and set(EXTENSIONS.values()) <= by_name.keys(),
                      "native readback extension routes are missing")
            self.state["extension_contracts"] = {name: by_name[name] for name in EXTENSIONS.values()}
        self.state["tools"] = q.artifact_json(
            self.root, str(self.output.relative_to(self.root) / "tools.json"), tools)

    def call(self, name, operation, arguments):
        q.require(name not in {row["id"] for row in self.rows}, "duplicate family case ID")
        if operation in EXTENSIONS:
            q.require(self.label == "native", "native extensions cannot be compared as original operations")
            tool = EXTENSIONS[operation]
        else:
            tool = ALIASES[operation] if self.label == "native" else operation
        start_index = len(self.client.entries)
        start = time.monotonic()
        response = self.client.call(tool, arguments)
        q.require(response.get("jsonrpc") == "2.0" and "result" in response and "error" not in response,
                  "public call returned an RPC failure or an invalid envelope")
        frames = {direction: [] for direction in ("sent", "received")}
        for entry in self.client.entries[start_index:]:
            raw = self.client.original(entry)
            decoded = q.parse_json(raw)
            if decoded.get("id") == response["id"]:
                frames[entry["direction"]].append((entry, raw, decoded))
        q.require(all(len(rows) == 1 for rows in frames.values()), "request/response wire is missing or duplicated")
        sent, received = frames["sent"][0], frames["received"][0]
        q.require(q.json_equal(sent[2].get("params"), {"name": tool, "arguments": arguments})
                  and sent[2].get("method") == "tools/call" and q.json_equal(received[2], response),
                  "retained original frames do not bind the actual tool call")
        # Decode text only for internal consistency and semantic checks. The row
        # and comparator below retain the original, unparsed CallToolResult.
        q.tool_value(response)
        row = {"id": name, "operation": operation, "arguments": arguments,
               "response": response, "response_bytes": received[0]["raw_bytes"],
               "response_sha256": received[0]["raw_sha256"], "seconds": time.monotonic() - start}
        path = self.output / (f"call-{len(self.rows) + 1:02d}-{name}.json.gz")
        saved = archive_raw(self.root, path, q.json_bytes(row))
        self.rows.append(row)
        self.state["rows"].append({"id": name, "operation": operation, "artifact": saved,
                                   "request_wire": {**sent[0], "path": str((self.output / sent[0]["path"]).relative_to(self.root))},
                                   "response_wire": {**received[0], "path": str((self.output / received[0]["path"]).relative_to(self.root))}})
        return response

    def export(self, name, path, expected, expected_raw=None):
        response = self.call(name, "export_evidence_bundle", {"path": str(path), "overwrite": True})
        raw, observed = read_stable(path, MAX_EXPORT_BYTES)
        result = payload(response, target=False)["result"]
        q.require(q.json_equal(result, {"path": str(path), "bytes": len(raw),
                                        "records": len(expected), "unknowns": 0}), "export receipt differs")
        bundle = validate_bundle(q.parse_json(raw), expected)
        q.require(raw == canonical_json(bundle), "export bytes are not the complete canonical bundle")
        if expected_raw is not None:
            q.require(raw == expected_raw, "export/import or rejected import changed complete canonical bytes")
        self.state["exports"][name] = {"file": observed,
            "artifact": archive_raw(self.root, self.output / (name + ".bundle.json.gz"), raw)}
        return raw, bundle

    def close(self):
        self.state["close"] = self.client.close()
        self.state["wire_index"] = q.artifact_reference(self.output / "wire.jsonl", self.root)
        self.state["launch"] = q.artifact_reference(self.output / "launch.json", self.root)
        self.state["close_artifact"] = q.artifact_reference(self.output / "close.json", self.root)
        self.state["stderr"] = q.artifact_reference(self.output / "stderr.log", self.root)
        q.require(closed_normally(self.state["close"]), "MCP owner required forced cleanup or left a child/reader")


def check_real_record(record, fixture):
    q.require(record["evidence_id"] == q.semantic_evidence_id(record)
              and q.json_equal(record["provider"], q.PROVIDER) and record["operation"] == "inspect_elf_notes"
              and q.json_equal(record["normalized_result"]["artifact"], fixture)
              and q.json_equal(record["parameters"], {"path": fixture["path"], "max_entries": 256,
                                                     "max_file_bytes": MAX_INPUT_BYTES}),
              "pinned real ELF is not bound to the complete observed record")


def check_overflow_record(record, fixture):
    facts = {**fixture, "entries": 1, "tables": 1, "format": "elf64", "byte_order": "little",
             "owner": "GNU", "descriptor_hex": None}
    q.check_independent_facts(record, {"facts": facts, "arguments": {"path": fixture["path"]}})
    entry = record["normalized_result"]["entries"][0]
    text = entry["gnu"]["build_id_hex"]
    q.require(entry["namesz"] == 4 and entry["descsz"] == DESCRIPTOR_BYTES
              and entry["descriptor"]["location"] == {"offset": 136, "bytes": DESCRIPTOR_BYTES}
              and entry["descriptor"]["sha256"] == DESCRIPTOR_SHA256
              and len(text) == DESCRIPTOR_BYTES * 2
              and text == (bytes(range(256)) * (DESCRIPTOR_BYTES // 256)).hex(),
              "oversized export omitted or altered independently encoded descriptor bytes")


def exercise_producer(session, fixtures, workspace):
    complete(session.call("empty", "get_evidence_bundle", {}), [])
    real = q.evidence_value(session.call("real-elf", "inspect_elf_notes",
                                       {"path": fixtures["real"]["path"], "max_entries": 256}))
    check_real_record(real, fixtures["real"])
    duplicate = q.evidence_value(session.call("real-repeat", "inspect_elf_notes",
                                            {"path": fixtures["real"]["path"], "max_entries": 256}))
    q.require(q.json_equal(real, duplicate), "same real input changed the complete record")
    small = q.evidence_value(session.call("controlled-elf", "inspect_elf_notes", {"path": fixtures["small"]["path"]}))
    q.check_independent_facts(small, {"arguments": {"path": fixtures["small"]["path"]},
        "facts": {**fixtures["small"], "entries": 1, "tables": 1, "owner": "GNU",
                  "descriptor_hex": bytes(range(20)).hex(), "format": "elf64", "byte_order": "little"}})
    records = [real, small]
    complete(session.call("small-complete", "get_evidence_bundle", {}), records)
    summary(session.call("small-summary", "get_evidence_bundle", {"detail": "summary"}), records)
    summary(session.call("small-summary-repeat", "get_evidence_bundle", {"detail": "summary"}), records)
    filters = {"evidence_id": real["evidence_id"]}
    summary(session.call("small-filtered-summary", "get_evidence_bundle", {"detail": "summary", "filters": filters}), records, filters)
    failures = (
        ("corrupt-elf", {"path": fixtures["corrupt"]["path"]}),
        ("file-budget", {"path": fixtures["small"]["path"], "max_file_bytes": 64}),
        ("entry-budget", {"path": fixtures["two-notes"]["path"], "max_entries": 1}),
        ("missing-elf", {"path": str(workspace / "absent.elf")}),
        ("invalid-limit", {"path": fixtures["small"]["path"], "max_entries": False}),
    )
    for name, arguments in failures:
        public_error(session.call(name, "inspect_elf_notes", arguments))
    complete(session.call("failed-inputs-unchanged", "get_evidence_bundle", {}), records)
    session.export("export-small", workspace / "small.json", records)
    limits = overflow(session.call("body-overflow", "inspect_elf_notes", {"path": fixtures["overflow"]["path"]}), "inspect_elf_notes")
    parent_id = limits["evidence_id"]
    q.require(re.fullmatch(r"ev_[0-9a-f]{64}", parent_id) is not None
              and limits["evidence_reference"] == {"kind": "retained-evidence", "evidence_id": parent_id},
              "completed overflow did not return its retained reference")
    discovery = payload(session.call("overflow-summary", "get_evidence_bundle", {"detail": "summary"}))["result"]
    q.require(discovery["total_retained_records"] == 3 and discovery["matching_records"] == 3
              and discovery["unknown_revisions"] == 0
              and [r["evidence_id"] for r in discovery["records"]] == sorted([real["evidence_id"], small["evidence_id"], parent_id]),
              "body overflow lost its complete retained record")
    overflow(session.call("bundle-overflow", "get_evidence_bundle", {}), "get_evidence_bundle")
    unsupported_elf_view(session.call("elf-view-unsupported", "inspect_analysis_view",
        {"source": {"kind": "retained-evidence", "evidence_id": parent_id}, "view": {"kind": "summary"}}))
    # The exact third record can only be obtained through the export route in
    # this frozen profile; a summary is never used as a substitute for it.
    response = session.call("export-full", "export_evidence_bundle", {"path": str(workspace / "full.json"), "overwrite": True})
    raw, file_identity = read_stable(workspace / "full.json", MAX_EXPORT_BYTES)
    q.require(q.json_equal(payload(response, target=False)["result"],
                          {"path": str(workspace / "full.json"), "bytes": len(raw), "records": 3, "unknowns": 0}),
              "full overflow export receipt differs")
    bundle = validate_bundle(q.parse_json(raw))
    q.require(len(bundle["records"]) == 3 and raw == canonical_json(bundle), "full export is incomplete or noncanonical")
    parent = next((record for record in bundle["records"] if record["evidence_id"] == parent_id), None)
    q.require(parent is not None, "export omitted the exact overflow reference")
    check_overflow_record(parent, fixtures["overflow"])
    validate_bundle(bundle, records + [parent])
    session.state["exports"]["export-full"] = {"file": file_identity,
        "artifact": archive_raw(session.root, session.output / "export-full.bundle.json.gz", raw)}
    summary(session.call("post-export-summary", "get_evidence_bundle", {"detail": "summary"}), bundle["records"])
    return raw, bundle, parent_id


def import_sources(workspace, raw, bundle):
    changed = q.parse_json(raw)
    changed["records"][-1]["normalized_result"]["artifact"]["bytes"] += 1
    q.require(changed["records"][-1]["evidence_id"] != q.semantic_evidence_id(changed["records"][-1]),
              "negative import fixture did not invalidate its unchanged Evidence ID")
    values = {"original-source.json": raw, "truncated-source.json": raw[:-1],
              "tampered-source.json": canonical_json(changed)}
    return {name: write_new(workspace / name, value) for name, value in values.items()}


def exercise_restore(session, workspace, raw, bundle, parent_id):
    records = bundle["records"]
    complete(session.call("empty", "get_evidence_bundle", {}), [])
    counts(session.call("import-full", "import_evidence_bundle", {"path": str(workspace / "original-source.json")}), 3, 3)
    summary(session.call("summary", "get_evidence_bundle", {"detail": "summary"}), records)
    counts(session.call("import-repeat", "import_evidence_bundle", {"path": str(workspace / "original-source.json")}), 0, 3)
    summary(session.call("summary-repeat", "get_evidence_bundle", {"detail": "summary"}), records)
    overflow(session.call("bundle-overflow", "get_evidence_bundle", {}), "get_evidence_bundle")
    unsupported_elf_view(session.call("elf-view-unsupported", "inspect_analysis_view",
        {"source": {"kind": "retained-evidence", "evidence_id": parent_id}, "view": {"kind": "summary"}}))
    session.export("export-restored", workspace / "restored.json", records, raw)
    for name, filename in (("truncated", "truncated-source.json"), ("tampered", "tampered-source.json"),
                           ("missing", "absent-source.json")):
        failure = public_error(session.call("import-" + name, "import_evidence_bundle", {"path": str(workspace / filename)}))
        if name in {"truncated", "tampered"}:
            q.require(failure["code"] == "evidence_integrity_mismatch", "invalid Evidence did not produce an integrity refusal")
        session.export("after-" + name, workspace / "restored.json", records, raw)
    summary(session.call("final-summary", "get_evidence_bundle", {"detail": "summary"}), records)


def exercise_cold(session, workspace, raw, bundle):
    complete(session.call("empty", "get_evidence_bundle", {}), [])
    counts(session.call("import-restored", "import_evidence_bundle", {"path": str(workspace / "restored.json")}), 3, 3)
    summary(session.call("summary", "get_evidence_bundle", {"detail": "summary"}), bundle["records"])
    session.export("export-cold", workspace / "cold.json", bundle["records"], raw)


def readback_page(response, expected, records, offset, requested_length, snapshot_id=None):
    """Check exact independent bytes, every continuation field and both hashes."""
    page = payload(response)["result"]
    q.require(set(page) == {"profile", "snapshot_id", "sha256", "total_bytes", "records", "unknowns",
                           "encoding", "offset", "length", "bytes_hex", "chunk_sha256", "next_offset", "eof", "persistence"},
              "native page contract fields differ")
    digest = hashlib.sha256(expected).hexdigest()
    wanted_id = "ebs1_" + digest
    q.require(snapshot_id is None or snapshot_id == wanted_id, "page switched the selected snapshot")
    q.require(0 <= offset <= len(expected) and 1 <= requested_length <= 262144,
              "invalid independent page expectation")
    end = min(offset + requested_length, len(expected))
    chunk = expected[offset:end]
    wanted = {"profile": READBACK_PROFILE, "snapshot_id": wanted_id, "sha256": digest,
              "total_bytes": len(expected), "records": records, "unknowns": 0, "encoding": "hex",
              "offset": offset, "length": len(chunk), "bytes_hex": chunk.hex(),
              "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
              "next_offset": None if end == len(expected) else end, "eof": end == len(expected),
              "persistence": "session-only"}
    q.require(q.json_equal(page, wanted), "native page bytes, coverage, identity or digest differ from export")
    return page


def snapshot_release(response, snapshot_id, released, released_bytes, retained_snapshots, retained_bytes):
    q.require(q.json_equal(payload(response)["result"], {
        "profile": READBACK_PROFILE, "snapshot_id": snapshot_id, "released": released,
        "released_bytes": released_bytes, "retained_snapshots": retained_snapshots,
        "retained_bytes": retained_bytes}), "snapshot release accounting differs")


def exercise_extension(session, fixtures, workspace, original_raw, original_bundle):
    complete(session.call("empty", "get_evidence_bundle", {}), [])
    counts(session.call("import-full", "import_evidence_bundle", {"path": str(workspace / "original-source.json")}), 3, 3)
    first = readback_page(session.call("freeze-original", "read_evidence_bundle", {}), original_raw, 3, 0, 65536)
    old_id = first["snapshot_id"]
    # A distinct admitted parameter value produces a fourth actual observation.
    # No fabricated Evidence is used to exercise snapshot isolation.
    grown = q.evidence_value(session.call("new-observation", "inspect_elf_notes",
        {"path": fixtures["unicode"]["path"], "max_entries": 31}))
    q.check_independent_facts(grown, {"arguments": {"path": fixtures["unicode"]["path"], "max_entries": 31},
        "facts": {**fixtures["unicode"], "entries": 1, "tables": 1, "owner": "GNU",
                  "descriptor_hex": bytes(range(20)).hex(), "format": "elf64", "byte_order": "little"}})
    q.require(grown["evidence_id"] not in {r["evidence_id"] for r in original_bundle["records"]},
              "new actual observation did not change the live registry")
    expanded_raw, _ = session.export("export-expanded", workspace / "expanded.json",
                                     original_bundle["records"] + [grown])
    q.require(expanded_raw != original_raw, "live registry did not grow after snapshot creation")
    replay = readback_page(session.call("replay-before-continuation", "read_evidence_bundle",
        {"snapshot_id": old_id, "offset": 0, "length": 65536}), original_raw, 3, 0, 65536, old_id)
    q.require(q.json_equal(first, replay), "replaying a fixed page after new Evidence changed it")
    invalid = (
        ("missing-cursor", {"offset": 1, "length": 1}),
        ("zero-length", {"snapshot_id": old_id, "offset": 0, "length": 0}),
        ("excessive-length", {"snapshot_id": old_id, "offset": 0, "length": 262145}),
        ("out-of-range", {"snapshot_id": old_id, "offset": len(original_raw) + 1, "length": 1}),
        ("unknown-cursor", {"snapshot_id": "ebs1_" + "0" * 64, "offset": 0, "length": 1}),
        ("malformed-cursor", {"snapshot_id": "ebs1_invalid", "offset": 0, "length": 1}),
    )
    for name, arguments in invalid:
        public_error(session.call(name, "read_evidence_bundle", arguments))
    reconstructed = bytearray(bytes.fromhex(first["bytes_hex"]))
    page, page_count = first, 1
    while not page["eof"]:
        q.require(page_count < 65 and page["next_offset"] == len(reconstructed), "nonprogressing page continuation")
        offset = page["next_offset"]
        page = readback_page(session.call(f"continuation-{page_count:02d}", "read_evidence_bundle",
            {"snapshot_id": old_id, "offset": offset, "length": 262144}), original_raw, 3, offset, 262144, old_id)
        reconstructed.extend(bytes.fromhex(page["bytes_hex"]))
        page_count += 1
    q.require(bytes(reconstructed) == original_raw and page_count > 1,
              "complete native continuation did not reconstruct the original exported bytes")
    reconstructed_artifact = archive_raw(session.root, session.output / "reconstructed.bundle.json.gz", reconstructed)
    readback_page(session.call("exact-eof", "read_evidence_bundle",
        {"snapshot_id": old_id, "offset": len(original_raw), "length": 1}), original_raw, 3, len(original_raw), 1, old_id)
    fresh = readback_page(session.call("freeze-current", "read_evidence_bundle", {}), expanded_raw, 4, 0, 65536)
    new_id = fresh["snapshot_id"]
    q.require(new_id != old_id, "changed complete bundle reused the old snapshot identity")
    tail_offset = max(0, len(expanded_raw) - 137)
    readback_page(session.call("current-tail", "read_evidence_bundle",
        {"snapshot_id": new_id, "offset": tail_offset, "length": 137}), expanded_raw, 4, tail_offset, 137, new_id)
    split_offset = expanded_raw.index("中".encode("utf-8")) + 1
    readback_page(session.call("inside-utf8-codepoint", "read_evidence_bundle",
        {"snapshot_id": new_id, "offset": split_offset, "length": 1}), expanded_raw, 4, split_offset, 1, new_id)
    snapshot_release(session.call("release-original", "close_evidence_snapshot", {"snapshot_id": old_id}),
                     old_id, True, len(original_raw), 1, len(expanded_raw))
    public_error(session.call("released-cursor", "read_evidence_bundle", {"snapshot_id": old_id, "length": 1}))
    snapshot_release(session.call("release-original-repeat", "close_evidence_snapshot", {"snapshot_id": old_id}),
                     old_id, False, 0, 1, len(expanded_raw))
    # Leave exactly this observed current snapshot to normal owner EOF. The next
    # process must reject it even after the original Evidence has been imported.
    session.export("release-preserves-evidence", workspace / "expanded.json",
                   original_bundle["records"] + [grown], expanded_raw)
    return {"snapshot_id": new_id, "old_snapshot_id": old_id, "pages": page_count,
            "reconstructed": reconstructed_artifact, "current_bundle_sha256": hashlib.sha256(expanded_raw).hexdigest(),
            "checks": ["complete-continuation-equals-export", "old-page-replay-after-new-evidence",
                       "snapshot-keeps-old-complete-bundle", "current-snapshot-binds-new-export",
                       "offset-length-and-cursor-refusals", "exact-eof", "utf8-codepoint-split-preserves-bytes", "release-is-idempotent",
                       "released-cursor-refused", "release-preserves-evidence"]}


def exercise_extension_cold(session, workspace, original_raw, original_bundle, previous):
    complete(session.call("empty", "get_evidence_bundle", {}), [])
    for suffix, token in (("live", previous["snapshot_id"]), ("released", previous["old_snapshot_id"])):
        public_error(session.call("foreign-" + suffix, "read_evidence_bundle", {"snapshot_id": token, "length": 1}))
    counts(session.call("import-full", "import_evidence_bundle", {"path": str(workspace / "original-source.json")}), 3, 3)
    public_error(session.call("import-does-not-restore-cursor", "read_evidence_bundle",
                             {"snapshot_id": previous["old_snapshot_id"], "length": 1}))
    fresh = readback_page(session.call("explicit-fresh-snapshot", "read_evidence_bundle", {"length": 7}),
                         original_raw, 3, 0, 7)
    snapshot_release(session.call("release-fresh", "close_evidence_snapshot", {"snapshot_id": fresh["snapshot_id"]}),
                     fresh["snapshot_id"], True, len(original_raw), 0, 0)
    public_error(session.call("released-fresh-cursor", "read_evidence_bundle", {"snapshot_id": fresh["snapshot_id"], "length": 1}))
    session.export("unchanged-after-release", workspace / "extension-cold.json", original_bundle["records"], original_raw)
    return {"checks": ["new-owner-rejects-previous-snapshot", "import-does-not-implicitly-restore-cursor",
                       "explicit-new-snapshot", "release-restores-zero-accounting", "cold-release-preserves-evidence"]}


def compare_row(original, native):
    q.require(original["id"] == native["id"] and original["operation"] == native["operation"]
              and q.json_equal(original["arguments"], native["arguments"]), "differential inputs differ")
    left, right = original["response"], native["response"]
    q.require("result" in left and "result" in right and "error" not in left and "error" not in right,
              "missing complete public CallToolResult")
    equal = q.json_equal(left["result"], right["result"])
    return {"id": original["id"], "status": "PASS" if equal else "FAIL",
            "complete_call_tool_result_equal": equal,
            "opaque_text_equal": q.json_equal(left["result"].get("content"), right["result"].get("content")),
            "jsonrpc_object_equal": q.json_equal(left, right),
            "raw_jsonrpc_frame_equal": (original["response_sha256"] == native["response_sha256"]
                                         and original["response_bytes"] == native["response_bytes"])}


def complete_sequences(sessions):
    return (set(sessions) == {(label, scenario) for label in ("reference", "native") for scenario in EXPECTED_CASES}
            and all(tuple(row["id"] for row in session.rows) == EXPECTED_CASES[scenario]
                    and closed_normally(session.state.get("close", {}))
                    for (label, scenario), session in sessions.items()))


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "binary", "reference-package", "reference-tarball", "node", "input-elf", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--input-elf-sha256", required=True)
    parser.add_argument("--node-sha256", default=NODE_SHA256)
    parser.add_argument("--build-summary", type=Path)
    parser.add_argument("--build-summary-sha256")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)), "all paths must be absolute")
    q.require((args.build_summary is None) == (args.build_summary_sha256 is None), "build summary and digest must be supplied together")
    for name in ("binary_sha256", "input_elf_sha256", "node_sha256"):
        q.require(re.fullmatch(r"[0-9a-f]{64}", getattr(args, name)) is not None, "invalid SHA256 pin: " + name)
    q.require(Path(__file__).resolve() == (args.repo / "scripts" / Path(__file__).name).resolve(),
              "run the selected repository's family qualification script")
    output = args.output_dir
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "profile": PROFILE, "qualified": False, "status": "OPEN",
              "finite_status": "FAIL", "open_requirements": list(OPEN_REQUIREMENTS),
              "scope": "actual Linux original/native ELF and Evidence export/import; no operation-ledger promotion",
              "analysis_view": "ELF unsupported in frozen upstream; tested as a refusal, not as pagination",
              "native_extensions": {"finite_status": "NOT_RUN", "profile": READBACK_PROFILE},
              "sessions": {}, "comparisons": [], "errors": []}
    sessions, extension_sessions, sources, fixtures = {}, {}, {}, {}
    monitor = selection = before = None
    original_raw = original_bundle = original_parent = None
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "native binary pin differs")
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["reference_before"]["files_sha256"] == q.PACKAGE_FILES_SHA256
                  and report["reference_before"]["file_count"] == 2398, "installed frozen npm inventory differs")
        report["node_before"] = q.identity(args.node.resolve())
        q.require(report["node_before"]["sha256"] == args.node_sha256, "Node executable pin differs")
        version = subprocess.run([str(args.node), "--version"], capture_output=True, check=True, timeout=10, env={})
        report["node_version"] = version.stdout.decode().strip()
        q.require(report["node_version"] == "v22.23.4", "this profile requires Node 22.23.4")
        report["python"] = {"version": sys.version, "binary": q.identity(Path(sys.executable).resolve())}
        selection = Selection(args.repo, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        report["source_before"] = q.artifact_json(output, "source-before.json", before)
        if args.build_summary is not None:
            from rea_build_evidence import capture_build
            bundle, binding = capture_build(args.build_summary, args.build_summary_sha256, output,
                                            before, report["binary_before"])
            report["build_evidence"], report["build_binding"] = bundle, binding
            report["open_requirements"].remove("full-final-combination-build-source-attestation")
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        raw, report["real_input_before"] = read_stable(args.input_elf, MAX_INPUT_BYTES)
        q.require(report["real_input_before"]["sha256"] == args.input_elf_sha256
                  and len(raw) >= 64 and raw.startswith(b"\x7fELF"), "real input pin or ELF header differs")
        fixture_bytes = {"real": raw, "small": q.elf(q.note()), "unicode": q.elf(q.note()), "overflow": oversized_elf(),
                         "corrupt": q.elf(q.note())[:-1], "two-notes": q.elf(q.note() + q.note())}
        for name, data in fixture_bytes.items():
            filename = "unicode-中文-🙂.elf" if name == "unicode" else name + ".elf"
            fixtures[name] = write_new(workspace / filename, data)
        del fixture_bytes, raw
        report["fixtures"] = q.artifact_json(output, "fixtures.json", fixtures)
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
            "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(output / "unused-remote"),
                "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full",
                       "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        producers = (("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], environment),
                     ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}))
        for label, command, env in producers:
            try:
                for scenario in EXPECTED_CASES:
                    session = Session(label, scenario, command, env, workspace,
                                      output / (label + "-" + scenario), output, report)
                    sessions[(label, scenario)] = session
                    session.initialize()
                    if scenario == "producer":
                        produced_raw, produced_bundle, parent_id = exercise_producer(session, fixtures, workspace)
                        if label == "reference":
                            original_raw, original_bundle, original_parent = produced_raw, produced_bundle, parent_id
                            sources = import_sources(workspace, original_raw, original_bundle)
                            report["shared_import_inputs"] = q.artifact_json(output, "shared-import-inputs.json", sources)
                    else:
                        q.require(original_raw is not None, "the original complete shared import input was not produced")
                        for identity in sources.values():
                            q.require(q.identity(identity["path"]) == identity, "shared differential import input changed")
                        if scenario == "restore":
                            exercise_restore(session, workspace, original_raw, original_bundle, original_parent)
                        else:
                            exercise_cold(session, workspace, original_raw, original_bundle)
                    session.close()
            except Exception as error:
                report["errors"].append({"producer": label, "type": type(error).__name__, "message": str(error)})
            finally:
                for (owner, scenario), session in sessions.items():
                    if owner == label and not session.client.closed:
                        try:
                            session.close()
                        except Exception as error:
                            report["errors"].append({"producer": label, "stage": "close", "type": type(error).__name__, "message": str(error)})
        if original_raw is not None:
            try:
                native_command = producers[1][1]
                extension = Session("native", "extension", native_command, {}, workspace,
                                    output / "native-extension", output, report)
                extension_sessions["extension"] = extension
                extension.initialize()
                observed = exercise_extension(extension, fixtures, workspace, original_raw, original_bundle)
                extension.close()
                cold = Session("native", "extension-cold", native_command, {}, workspace,
                               output / "native-extension-cold", output, report)
                extension_sessions["extension-cold"] = cold
                cold.initialize()
                cold_observed = exercise_extension_cold(cold, workspace, original_raw, original_bundle, observed)
                cold.close()
                report["native_extensions"] = {"finite_status": "PASS", "profile": READBACK_PROFILE,
                    "comparison_scope": "native-only; independent canonical export bytes, no Node-equivalence claim",
                    "active_session": observed, "new_session": cold_observed,
                    "closed_owners": 2}
            except Exception as error:
                report["native_extensions"]["finite_status"] = "FAIL"
                report["errors"].append({"stage": "native-extensions", "type": type(error).__name__, "message": str(error)})
        for scenario in EXPECTED_CASES:
            if not all((label, scenario) in sessions for label in ("reference", "native")):
                continue
            left, right = (sessions[(label, scenario)] for label in ("reference", "native"))
            q.require([row["id"] for row in left.rows] == [row["id"] for row in right.rows], "producer case sequences differ")
            for old, new in zip(left.rows, right.rows, strict=True):
                report["comparisons"].append({**compare_row(old, new), "id": scenario + "/" + old["id"]})
            contracts_equal = q.json_equal(left.state["contracts"], right.state["contracts"])
            report["comparisons"].append({"id": scenario + "/contracts", "status": "PASS" if contracts_equal else "FAIL"})
            q.require(left.state["exports"].keys() == right.state["exports"].keys(), "export attempt sequences differ")
            for name in left.state["exports"]:
                old, new = (session.state["exports"][name]["artifact"] for session in (left, right))
                same = old["raw_bytes"] == new["raw_bytes"] and old["raw_sha256"] == new["raw_sha256"]
                report["comparisons"].append({"id": scenario + "/" + name + "-canonical-bytes", "status": "PASS" if same else "FAIL"})
    except Exception as error:
        report["errors"].append({"stage": "execution", "type": type(error).__name__, "message": str(error)})
    finally:
        for session in list(sessions.values()) + list(extension_sessions.values()):
            if not session.client.closed:
                try:
                    session.close()
                except Exception as error:
                    report["errors"].append({"stage": "cleanup", "type": type(error).__name__, "message": str(error)})
        if monitor is not None:
            try:
                events = monitor.stop()
                after = selection.snapshot()
                report["source_after"] = q.artifact_json(output, "source-after.json", after)
                report["source_events"] = q.artifact_json(output, "source-events.json", events)
                q.require(q.json_equal(before, after) and events["event_count"] == 0 and events["errors"] == [],
                          "selected source changed or monitor coverage was lost")
                report["source_unchanged"] = True
            except Exception as error:
                report["errors"].append({"stage": "source", "type": type(error).__name__, "message": str(error)})
        try:
            for name, path in (("binary", args.binary), ("node", args.node.resolve()), ("real_input", args.input_elf)):
                report[name + "_after"] = q.identity(path)
                q.require(q.json_equal(report.get(name + "_before"), report[name + "_after"]), "identity changed: " + name)
            report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
            q.require(q.json_equal(report.get("reference_before"), report["reference_after"]), "frozen original package changed")
            for identity in list(fixtures.values()) + list(sources.values()):
                q.require(q.identity(identity["path"]) == identity, "selected input changed during execution")
        except Exception as error:
            report["errors"].append({"stage": "identity", "type": type(error).__name__, "message": str(error)})
    report["sequences_complete"] = complete_sequences(sessions)
    report["observed_cases"] = {label + "/" + scenario: [row["id"] for row in session.rows]
                                for (label, scenario), session in sessions.items()}
    report["expected_cases"] = {scenario: list(names) for scenario, names in EXPECTED_CASES.items()}
    passed = sum(row["status"] == "PASS" for row in report["comparisons"])
    expected_comparisons = sum(map(len, EXPECTED_CASES.values())) + 3 + 7
    good = (not report["errors"] and report["sequences_complete"] and report.get("source_unchanged") is True
            and report["native_extensions"]["finite_status"] == "PASS"
            and len(report["comparisons"]) == expected_comparisons and passed == expected_comparisons)
    report["finite_status"] = "PASS" if good else "FAIL"
    report["status"] = "OPEN" if good else "FAILED"
    report["counts"] = {"comparisons": len(report["comparisons"]), "passed": passed,
        "complete_call_tool_results": sum("complete_call_tool_result_equal" in row for row in report["comparisons"]),
        "raw_jsonrpc_frame_matches": sum(row.get("raw_jsonrpc_frame_equal") is True for row in report["comparisons"]),
        "native_extension_calls": sum(len(session.rows) for session in extension_sessions.values())}
    receipt = q.write_json(output / "qualification.json", report)
    print(json.dumps({"finite_status": report["finite_status"], "qualified": False, "counts": report["counts"],
                      "errors": report["errors"], "receipt": receipt}, sort_keys=True))
    return 0 if good else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"qualified": False, "status": "INVALID", "error": str(error)}), file=sys.stderr)
        sys.exit(2)
