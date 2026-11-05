#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Actual REA/native body-overflow, retained pages and complete export recovery.

The fixture adds three unknown digest declarations to a frozen APK signing
block. Both actual parsers must preserve those bytes and report their status as
unknown. This is controlled static input, not a signature-valid APK or a real
engine qualification. The 10 MiB response budget is never raised or lowered.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import rea_analysis_view_qualification as views
import rea_apk_export_qualification as a
import rea_apk_path_alias_qualification as alias
import rea_operation_qualification as q
from rea_frame_mcp_qualification import CompressedMcp
from rea_full_qualification import Selection, SourceMonitor


DIGEST_BYTES = 1024 * 1024
FIXTURE_SHA256 = "a3e97d41fe8c3061691bee34332f0dcb7c5fc69a21145097b93a32a3e869d366"
OPEN_REQUIREMENTS = ["other-analysis-view-kinds", "all-evidence-import-profiles",
                     "active-cancellation-differential", "all-resource-boundaries",
                     "full-final-combination-build-receipt", "cross-platform-behavior"]


def oversized_apk(original):
    """Preserve all original bytes except one signer and its enclosing lengths."""
    q.require(hashlib.sha256(original).hexdigest() == alias.FIXTURE_SHA256,
              "frozen APK fixture changed")
    end = original.rfind(b"PK\x05\x06")
    q.require(end >= 0 and end + 22 == len(original), "unexpected ZIP tail")
    _, directory = struct.unpack_from("<II", original, end + 12)
    q.require(original[directory - 16:directory] == b"APK Sig Block 42", "signing block missing")
    start = directory - struct.unpack_from("<Q", original, directory - 24)[0] - 8

    def prefixed(value):
        return struct.pack("<I", len(value)) + value

    def take(value, offset):
        q.require(offset + 4 <= len(value), "missing length")
        length = struct.unpack_from("<I", value, offset)[0]
        q.require(offset + 4 + length <= len(value), "invalid original length")
        return value[offset + 4:offset + 4 + length], offset + 4 + length

    pairs, position, changed = [], start + 8, 0
    while position < directory - 24:
        length = struct.unpack_from("<Q", original, position)[0]
        identity = struct.unpack_from("<I", original, position + 8)[0]
        q.require(length >= 4 and position + 8 + length <= directory - 24,
                  "invalid signing-block pair")
        value = original[position + 12:position + 8 + length]
        if identity == 0x7109871A:
            sequence, suffix = take(value, 0)
            signer, remainder = take(sequence, 0)
            signed, after = take(signer, 0)
            digests, digest_end = take(signed, 0)
            extra = b"".join(prefixed(struct.pack("<I", 0xF00D0000 + index)
                                     + prefixed(bytes([index + 1]) * DIGEST_BYTES))
                             for index in range(3))
            updated = prefixed(prefixed(digests + extra) + signed[digest_end:]) + signer[after:]
            value = prefixed(prefixed(updated) + sequence[remainder:]) + value[suffix:]
            changed += 1
        pairs.append(struct.pack("<Q", 4 + len(value)) + struct.pack("<I", identity) + value)
        position += 8 + length
    q.require(changed == 1 and position == directory - 24, "unexpected v2 block multiplicity")
    pairs = b"".join(pairs)
    block = (struct.pack("<Q", len(pairs) + 24) + pairs + struct.pack("<Q", len(pairs) + 24)
             + b"APK Sig Block 42")
    tail = bytearray(original[end:])
    struct.pack_into("<I", tail, 16, start + len(block))
    result = original[:start] + block + original[directory:end] + bytes(tail)
    q.require(hashlib.sha256(result).hexdigest() == FIXTURE_SHA256,
              "controlled overflow fixture bytes changed")
    return result


def error(value):
    q.require(value.get("isError") is True and "rpc_error" not in value,
              "expected a tool error, not an SDK or connection failure")
    return value["content"][0]["text"]["error"]


def overflow(value, operation):
    failure = error(value)
    limits = failure["details"]["reported_limits"]
    q.require(failure["code"] == "resource_constraint" and failure["retryable"] is False
              and failure["details"]["operation"] == operation
              and failure["details"]["resource"] == "transport"
              and limits["boundary"] == "mcp-response"
              and limits["default_receive_buffer_bytes"] == 10 * 1024 * 1024
              and limits["result_budget_bytes"] == 10 * 1024 * 1024 - 1024
              and limits["constraint"] == "receive-buffer"
              and limits["response_bytes_at_least"] > limits["result_budget_bytes"],
              "operation did not complete at the original body response boundary")
    return limits


def save_gzip(path, value):
    raw = q.json_bytes(value)
    with path.open("xb") as target:
        with gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as stream:
            stream.write(raw)
    return {"path": str(path), "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "gzip_bytes": path.stat().st_size, "gzip_sha256": q.file_hash(path)}


class Session:
    def __init__(self, label, scenario, command, environment, workspace, output, report):
        self.label, self.scenario, self.output = label, scenario, output
        self.client = CompressedMcp(command, workspace, environment, output)
        self.rows = []
        self.state = {"rows": [], "checks": []}
        report["sessions"][label + "/" + scenario] = self.state
        self.client.initialize()

    def call(self, name, operation, arguments):
        tool = views.ALIASES[operation] if self.label == "native" else operation
        response = self.client.call(tool, arguments)
        value = q.tool_value(response)
        row = {"id": name, "arguments": arguments, "value": value,
               "view_order": views.view_order(value)}
        self.rows.append(row)
        saved = save_gzip(self.output / (f"call-{len(self.rows):02d}-{name}.json.gz"),
                          {**row, "response": response})
        self.state["rows"].append({"id": name, "operation": operation, "artifact": saved})
        return value

    def close(self):
        self.state["close"] = self.client.close()
        q.require(a.closed_normally(self.state["close"]), "actual MCP owner did not drain")


def verify_export(bundle, parent_id, pages, summary):
    q.require(set(bundle) == a.BUNDLE_KEYS, "export changed the seven-array bundle contract")
    records = bundle["records"]
    q.require(len(records) == 8 and [item["evidence_id"] for item in records]
              == sorted(set(item["evidence_id"] for item in records)),
              "full parent, summary and six unique pages were not retained exactly")
    for record in records:
        q.require(q.semantic_evidence_id(record) == record["evidence_id"], "exported record digest differs")
    parent = next(record for record in records if record["evidence_id"] == parent_id)
    q.require(parent["operation"] == "inspect_apk_signature", "overflow reference did not select a full parent")
    q.require(all(record in records for record in [summary, *pages]), "observed page bytes were not retained in full")
    expected = []
    report = parent["normalized_result"]
    for scheme in ("v2", "v3", "v3.1"):
        for signer_index, signer in enumerate(report["schemes"][scheme]["signers"]):
            signer_id = f"apk:{report['artifact']['sha256']}:{scheme}:signer:{signer_index}"
            for index, digest in enumerate(signer["digests"]):
                expected.append({**digest, "id": signer_id + ":digests:" + str(index),
                                 "scheme": scheme, "signer_id": signer_id,
                                 "signer_index": signer_index, "index": index})
    observed = [item for page in pages for item in page["normalized_result"]["items"]]
    q.require(len(expected) == 6 and observed == expected, "pagination lost, reordered or changed complete digest bytes")
    for index in range(3):
        item = next(item for item in observed if item["signature_algorithm_id"] == 0xF00D0000 + index)
        q.require(item["algorithm"] == "unknown" and item["matches_apk"] is None
                  and item["declared_digest_hex"] == f"{index + 1:02x}" * DIGEST_BYTES,
                  "unknown digest observation was truncated or interpreted as verified")
    return parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "reference-package", "reference-tarball", "node", "repo", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    args = parser.parse_args(argv)
    q.require(all(path.is_absolute() for path in vars(args).values() if isinstance(path, Path)),
              "all paths must be absolute")
    output = args.output_dir
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema": "hepta.rea.analysis-view-recovery.v1", "qualified": False,
              "status": "OPEN", "open_requirements": OPEN_REQUIREMENTS,
              "sessions": {}, "comparisons": [], "errors": []}
    sessions, monitor, selection = {}, None, None
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "frozen binary hash differs")
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["node"] = q.identity(args.node.resolve())
        q.require(report["node"]["sha256"] == a.NODE_SHA256, "unexpected Node binary")
        q.require(subprocess.check_output([str(args.node), "--version"], env={}, timeout=10, text=True).strip()
                  == "v22.23.4", "unexpected Node version")
        selection = Selection(args.repo, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        q.write_json(output / "producer-before.json", before)
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        apk, exported, corrupt = (workspace / name for name in ("overflow.apk", "bundle.json", "tampered.json"))
        apk.write_bytes(oversized_apk((args.repo / "tests/fixtures/rea_apk_signature/rotation-v31.apk").read_bytes()))
        report["fixture"] = {**q.identity(apk), "base_sha256": alias.FIXTURE_SHA256,
                             "additional_unknown_digests": 3, "digest_bytes_each": DIGEST_BYTES,
                             "scope": "Declared signing observations; signatures and authenticity remain unverified."}
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
                             "hosts": {"never-connect": {"ssh_target": "never-connect-invalid",
                                       "remote_state_dir": str(output / "unused-remote"), "allow_execute": False,
                                       "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                       "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        producers = (("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], environment),
                     ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}))
        for label, command, env in producers:
            session = Session(label, "main", command, env, workspace, output / (label + "-main"), report)
            sessions[(label, "main")] = session
            limits = overflow(session.call("body-overflow", "inspect_apk_signature",
                                           {"path": str(apk), "detail": "complete"}), "inspect_apk_signature")
            reference = limits["evidence_reference"]
            parent_id = limits["evidence_id"]
            q.require(reference == {"kind": "retained-evidence", "evidence_id": parent_id}, "unusable retained reference")
            discovery = a.payload(session.call("discovery", "get_evidence_bundle", {"detail": "summary"}))["result"]
            q.require(discovery["total_retained_records"] == 1 and len(discovery["records"]) == 1,
                      "completed overflow parent was not retained")
            summary = a.payload(session.call("summary", "inspect_analysis_view",
                                            {"source": reference, "view": {"kind": "summary"}}))
            pages = []
            offset = 0
            while True:
                q.require(offset == len(pages) and offset < 6, "invalid page continuation")
                page = a.payload(session.call("page-" + str(offset), "inspect_analysis_view", {
                    "source": reference, "view": {"kind": "apk-signature", "collection": "digests", "offset": offset, "limit": 1}}))
                coverage = page["normalized_result"]["coverage"]
                q.require(page["normalized_result"]["parent_evidence_id"] == parent_id
                          and coverage["status"] == "page" and coverage["examined"] == 1
                          and coverage["total"] == 6 and len(page["normalized_result"]["items"]) == 1,
                          "page omitted its parent identity or coverage")
                pages.append(page)
                if coverage["exhausted"]:
                    q.require(len(pages) == 6 and coverage["next_offset"] is None, "premature exhaustion")
                    break
                q.require(coverage["next_offset"] == offset + 1, "wrong next page")
                offset = coverage["next_offset"]
            overflow(session.call("bundle-overflow", "get_evidence_bundle", {}), "get_evidence_bundle")
            receipt = a.payload(session.call("export-complete", "export_evidence_bundle", {"path": str(exported)}), target=False)["result"]
            exported_identity = q.identity(exported)
            raw = exported.read_bytes()
            q.require(receipt["bytes"] == len(raw) and receipt["records"] == 8
                      and q.identity(exported) == exported_identity, "export receipt or stable bytes differ")
            with (session.output / "complete-bundle.json").open("xb") as handle:
                handle.write(raw)
            session.state["export"] = exported_identity
            parent = verify_export(q.parse_json(raw), parent_id, pages, summary)
            session.state["checks"].append({"id": "all-six-pages-reconstruct-full-export-digests", "status": "PASS"})
            imported = a.payload(session.call("import-complete", "inspect_analysis_view", {
                "source": {"kind": "evidence-file", "path": str(exported), "evidence_id": parent_id},
                "view": {"kind": "apk-signature", "collection": "digests", "offset": 1, "limit": 1}}))
            q.require(imported == pages[1], "imported complete parent changed the retained page")
            if label == "reference":
                tampered = copy.deepcopy(parent)
                tampered["normalized_result"]["artifact"]["bytes"] += 1
                q.write_json(corrupt, tampered)
                report["corrupt_input"] = q.identity(corrupt)
            failure = error(session.call("reject-tampered", "inspect_analysis_view", {
                "source": {"kind": "evidence-file", "path": str(corrupt)}, "view": {"kind": "summary"}}))
            q.require(failure["code"] == "evidence_integrity_mismatch", "tampered complete parent was accepted")
            retained = a.payload(session.call("after-import-and-error", "get_evidence_bundle", {"detail": "summary"}))["result"]
            q.require(retained["total_retained_records"] == 8, "import or rejected source changed retention")
            session.close()
            cold = Session(label, "cold", command, env, workspace, output / (label + "-cold"), report)
            sessions[(label, "cold")] = cold
            missing = error(cold.call("parent-absent", "inspect_analysis_view", {"source": reference, "view": {"kind": "summary"}}))
            q.require(missing["code"] == "evidence_integrity_mismatch", "retention leaked between server sessions")
            restored = a.payload(cold.call("import-page", "inspect_analysis_view", {
                "source": {"kind": "evidence-file", "path": str(exported), "evidence_id": parent_id},
                "view": {"kind": "apk-signature", "collection": "digests", "offset": 1, "limit": 1}}))
            q.require(restored == pages[1], "cold imported page changed")
            retained = a.payload(cold.call("only-derived-retained", "get_evidence_bundle", {"detail": "summary"}))["result"]
            q.require(retained["total_retained_records"] == 1 and retained["records"][0]["evidence_id"] == restored["evidence_id"],
                      "file selection silently imported the parent")
            cold.close()
            q.require(q.identity(exported) == exported_identity, "refusing to unlink changed owned export")
            exported.unlink()
        for scenario in ("main", "cold"):
            left, right = (sessions[(label, scenario)] for label in ("reference", "native"))
            q.require([row["id"] for row in left.rows] == [row["id"] for row in right.rows], "request sequences differ")
            for original, native in zip(left.rows, right.rows):
                differences = a.differences(original, native)
                report["comparisons"].append({"id": scenario + "/" + original["id"],
                                               "status": "PASS" if not differences else "FAIL",
                                               "differences": differences})
        reference_export = output / "reference-main/complete-bundle.json"
        native_export = output / "native-main/complete-bundle.json"
        same = reference_export.read_bytes() == native_export.read_bytes()
        report["comparisons"].append({"id": "export/complete-byte-equality", "status": "PASS" if same else "FAIL",
                                       "reference": q.identity(reference_export), "native": q.identity(native_export)})
        report["binary_after"] = q.identity(args.binary)
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["binary_before"] == report["binary_after"] and report["reference_before"] == report["reference_after"],
                  "frozen executable or npm package changed")
        q.require(q.file_hash(apk) == FIXTURE_SHA256 and q.identity(corrupt) == report["corrupt_input"], "input fixture changed")
        after = selection.snapshot()
        q.write_json(output / "producer-after.json", after)
        q.require(before == after, "qualification producer changed")
    except BaseException as exception:
        report["errors"].append(type(exception).__name__ + ": " + str(exception))
    finally:
        for session in sessions.values():
            if "close" not in session.state:
                try:
                    session.close()
                except BaseException as exception:
                    report["errors"].append("close: " + repr(exception))
        if monitor is not None:
            observed = monitor.stop()
            q.write_json(output / "producer-monitor.json", observed)
            if observed["event_count"] or observed["errors"]:
                report["errors"].append("producer source monitor changed or lost coverage")
        report["case_counts"] = {label + "/" + scenario: len(session.rows) for (label, scenario), session in sessions.items()}
        expected = {label + "/" + scenario: count for label in ("reference", "native") for scenario, count in (("main", 14), ("cold", 3))}
        report["passed_comparisons"] = sum(row["status"] == "PASS" for row in report["comparisons"])
        report["finite_status"] = "PASS" if report["case_counts"] == expected and len(report["comparisons"]) == 18 and report["passed_comparisons"] == 18 and not report["errors"] else "FAIL"
        report["status"] = "OPEN" if report["finite_status"] == "PASS" else "FAILED"
        receipt = q.write_json(output / "qualification.json", report)
        print(json.dumps({"qualified": False, "finite_status": report["finite_status"], "receipt": receipt,
                          "case_counts": report["case_counts"], "passed_comparisons": report["passed_comparisons"], "errors": report["errors"]}))
    return 0 if report["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
