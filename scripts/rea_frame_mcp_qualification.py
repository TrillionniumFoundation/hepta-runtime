#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Exercise the native final STDIO frame boundary through real MCP processes.

This is a finite native transport qualification, not upstream operation parity.
Every raw request and response is retained losslessly as an individual gzip file.
The original client's 30-second request, 15-second EOF, 16-MiB line and 256-MiB
received-transcript limits are unchanged. No output budget is raised for a test.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import time

import rea_apk_export_qualification as a
import rea_apk_path_alias_qualification as alias
import rea_operation_qualification as q
from rea_full_qualification import Selection, SourceMonitor


FRAME_BYTES = 10 * 1024 * 1024
LARGE_ID_HEADROOM = 8192
MODERN_META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
               "io.modelcontextprotocol/clientCapabilities": {}}
TOOL_NAMES = {"notes": "rea_inspect_elf_notes", "apk": "rea_inspect_apk_signature_evidence",
              "bundle": "rea_get_evidence_bundle", "export": "rea_export_evidence_bundle"}


def call_bytes(params, request_id):
    # Exactly q.Mcp.send's ordinary, non-raw_params serialization.
    return (json.dumps({"jsonrpc": "2.0", "method": "tools/call", "params": params,
                        "id": request_id}, ensure_ascii=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode()


def maximal_id(params, motif="i", limit=FRAME_BYTES):
    q.require(isinstance(motif, str) and motif, "ID motif must be a nonempty string")
    room = limit - len(call_bytes(params, ""))
    q.require(room >= 0, "parameters alone exceed the admitted frame")
    unit = len(json.dumps(motif, ensure_ascii=True).encode()) - 2
    value = motif * (room // unit) + "i" * (room % unit)
    q.require(len(call_bytes(params, value)) == limit, "ID did not fill the exact input boundary")
    return value


def id_facts(value):
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    return {"type": type(value).__name__, "json_token_bytes": len(encoded),
            "json_token_sha256": hashlib.sha256(encoded).hexdigest()}


class CompressedMcp(q.Mcp):
    """Change only durable log encoding, not requests, reads, waits or cleanup."""

    def __init__(self, *args):
        self.entries = []
        super().__init__(*args)

    def _log(self, direction, raw):
        with self.lock:
            number = len(self.entries)
            path = self.output / f"wire-{number:04d}-{direction}.json.gz"
            with path.open("xb") as stream:
                with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
                    zipped.write(raw)
            item = {"direction": direction, "monotonic_ns": time.monotonic_ns(),
                    "encoding": "gzip-original-jsonrpc-line", "path": path.name,
                    "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "gzip_bytes": path.stat().st_size, "gzip_sha256": q.file_hash(path)}
            self.entries.append(item)
            self.wire.write(json.dumps(item, sort_keys=True).encode() + b"\n")
            self.wire.flush()

    def original(self, entry):
        path = self.output / entry["path"]
        q.require(q.file_hash(path) == entry["gzip_sha256"], "compressed wire changed")
        with gzip.open(path, "rb") as stream:
            raw = stream.read(q.MAX_WIRE_BYTES + 1)
        q.require(len(raw) == entry["raw_bytes"] and len(raw) <= q.MAX_WIRE_BYTES
                  and hashlib.sha256(raw).hexdigest() == entry["raw_sha256"],
                  "original wire is not losslessly recoverable")
        return raw


class AllPackageFiles(Selection):
    def ignored(self, path):
        return False

    def source(self, path):
        return True


def validate_envelope(response, request_id, raw, cap=FRAME_BYTES):
    q.require(raw.endswith(b"\n") and len(raw) <= cap,
              "actual final JSON-RPC frame exceeds its fixed budget or lacks LF")
    q.require(q.parse_json(raw) == response, "returned value does not match the original wire")
    q.require(response.get("jsonrpc") == "2.0" and response.get("id") == request_id,
              "response did not preserve the exact admitted request ID")
    q.require(("result" in response) != ("error" in response), "ambiguous JSON-RPC result/error")


def success(response, modern=False, target=True):
    value = q.tool_value(response)
    a.payload(value, target=target)
    q.require((value.get("resultType") == "complete") if modern else ("resultType" not in value),
              "actual SDK resultType differs from the selected protocol")
    return value["structuredContent"]


def frame_refusal(response, operation, metadata, evidence_id=None, modern=False):
    value = q.tool_value(response)
    q.require(value.get("isError") is True and "rpc_error" not in value,
              "expected a bounded native transport tool refusal")
    body = value["content"][0]["text"]["error"]
    q.require(body["details"]["operation"] == operation, "refusal has stale operation context")
    limits = body["details"]["reported_limits"]
    q.require(limits["boundary"] == "native-mcp-frame" and limits["max_frame_bytes"] == FRAME_BYTES
              and limits["frame_bytes_at_least"] > FRAME_BYTES
              and limits["includes_request_id"] is True and limits["includes_newline"] is True,
              "refusal lost its precise final-frame boundary facts")
    q.require(value.get("_meta") == metadata, "finalized runtime metadata was lost or invented")
    if evidence_id is not None:
        q.require(limits["evidence_id"] == evidence_id and limits["evidence_reference"] == {
            "kind": "retained-evidence", "evidence_id": evidence_id}, "completed Evidence reference changed")
    q.require((value.get("resultType") == "complete") if modern else ("resultType" not in value),
              "replacement resultType differs from the selected protocol")


def rpc_refusal(response, empty=False):
    q.require("result" not in response and response.get("error", {}).get("code") == -32603,
              "expected a bounded internal protocol refusal")
    if empty:
        q.require(response["error"].get("message") == "", "minimal same-ID error was not used")


def check_build(args, output):
    build = json.loads(args.build_summary.read_bytes())
    checkpoint = json.loads(args.source_checkpoint.read_bytes())
    q.require(build["source_unchanged"] is True and build["source_before"] == build["source_after"],
              "build source is not bound before and after compilation")
    q.require(build.get("steps") and all(row["exit_code"] == 0 for row in build["steps"]),
              "build receipt includes a failed step")
    source = build["source_before"]
    rows = source["files"]
    q.require(rows == sorted(rows) and len({row[0] for row in rows}) == len(rows),
              "source manifest has duplicate or unordered paths")
    encoded = json.dumps(rows, separators=(",", ":")).encode()
    q.require(hashlib.sha256(encoded).hexdigest() == source["sha256"], "source manifest digest differs")
    q.require(checkpoint["source"]["files"] == rows
              and checkpoint["source"]["sha256"] == source["sha256"], "freeze and build source disagree")
    for name, digest in rows:
        parts = PurePosixPath(name).parts
        q.require(parts and not name.startswith("/") and ".." not in parts,
                  "unsafe source manifest path")
        q.require(q.file_hash(args.repo / name) == digest, "source differs from build: " + name)
    binary = q.identity(args.binary)
    q.require(binary["sha256"] == args.binary_sha256 == build["binary"]["sha256"]
              and binary["bytes"] == build["binary"]["bytes"], "binary and successful build disagree")
    copies = {}
    for label, path in (("build-summary", args.build_summary), ("source-checkpoint", args.source_checkpoint)):
        destination = output / (label + ".json")
        with destination.open("xb") as handle:
            handle.write(path.read_bytes())
        copies[label] = q.artifact_reference(destination, output)
    return {"binary": binary, "source_sha256": source["sha256"], "files": len(rows), "receipts": copies}


class Session:
    def __init__(self, client, state):
        self.client, self.state = client, state
        self.state.update({"rows": [], "checks": []})

    def exchange(self, name, params, request_id=None, verify=None):
        if request_id is None:
            request_id = self.client.next_id
            self.client.next_id += 1
        raw_request = call_bytes(params, request_id)
        q.require(len(raw_request) <= FRAME_BYTES, "test input exceeds private admission budget")
        first = len(self.client.entries)
        started = time.monotonic()
        self.client.send("tools/call", params, request_id=request_id)
        response = self.client.receive(request_id)
        entries = self.client.entries[first:]
        sent = [entry for entry in entries if entry["direction"] == "sent"]
        q.require(len(sent) == 1 and self.client.original(sent[0]) == raw_request,
                  "actual sent frame differs from the fixed case")
        received = [entry for entry in entries if entry["direction"] == "received"]
        matching = [(entry, self.client.original(entry)) for entry in received]
        matching = [(entry, raw) for entry, raw in matching if q.parse_json(raw) == response]
        q.require(len(matching) == 1, "response is missing or duplicated in preserved wire")
        entry, raw = matching[0]
        row = {"id": name, "request_id": id_facts(request_id), "input_bytes": len(raw_request),
               "output_bytes": len(raw), "seconds": time.monotonic() - started,
               "request_wire": sent[0], "response_wire": entry,
               "response_without_id": {key: value for key, value in response.items() if key != "id"}}
        self.state["rows"].append(row)
        try:
            validate_envelope(response, request_id, raw)
            if verify is not None:
                verify(response)
            row["status"] = "PASS"
        except (ValueError, KeyError, TypeError) as error:
            row.update(status="FAIL", error=type(error).__name__ + ": " + str(error))
        return response

    def check(self, name, verify):
        try:
            verify()
            self.state["checks"].append({"id": name, "status": "PASS"})
        except (ValueError, KeyError, TypeError) as error:
            self.state["checks"].append({"id": name, "status": "FAIL", "error": str(error)})


def params(tool, arguments=None, modern=False, omit=False):
    value = {"name": TOOL_NAMES[tool]}
    if not omit:
        value["arguments"] = {} if arguments is None else arguments
    if modern:
        value["_meta"] = dict(MODERN_META)
    return value


def run_main(session, workspace):
    parent = {}
    metadata = {}
    notes = {"path": str(workspace / "notes.elf")}
    apk = {"path": str(workspace / "rotation.apk"), "detail": "complete"}
    for label, tool, arguments in (("notes", "notes", notes), ("apk", "apk", apk)):
        for modern in (False, True):
            response = session.exchange(f"{label}-{'modern' if modern else 'legacy'}",
                                        params(tool, arguments, modern), verify=lambda r, m=modern: success(r, m))
            record = success(response, modern)
            parent[label] = record
            metadata[label] = response["result"].get("_meta")
            q.require(record["evidence_id"] == q.semantic_evidence_id(record), "independent parent digest differs")
    expected = sorted(parent.values(), key=lambda record: record["evidence_id"])

    def retained(response, modern=False):
        success(response, modern)
        bundle = a.complete_bundle(q.tool_value(response))
        q.require(bundle["records"] == expected, "frame refusal altered the complete retained records")

    for modern in (False, True):
        response = session.exchange("bundle-" + ("modern" if modern else "legacy"), params("bundle", modern=modern),
                                    verify=lambda r, m=modern: retained(r, m))
        metadata["bundle"] = response["result"].get("_meta")

    long_id = "t" * (FRAME_BYTES - LARGE_ID_HEADROOM - 2)
    for label, arguments, operation in (("notes", notes, "inspect_elf_notes"),
                                         ("apk", apk, "inspect_apk_signature"),
                                         ("bundle", {}, "get_evidence_bundle")):
        for modern in (False, True):
            session.exchange(f"frame-refusal-{label}-{'modern' if modern else 'legacy'}",
                             params(label, arguments, modern), request_id=long_id,
                             verify=lambda r, o=operation, k=label, m=modern: frame_refusal(
                                 r, o, metadata[k], parent[k]["evidence_id"] if k in parent else None, m))
    session.exchange("recovery-after-six-refusals", params("bundle"), verify=retained)

    for modern in (False, True):
        request = params("bundle", modern=modern, omit=True)
        huge = maximal_id(request)
        first = session.exchange("maximum-id-" + ("modern" if modern else "legacy"), request, huge,
                                 verify=lambda r, m=modern: rpc_refusal(r, empty=not m))
        if not modern:
            second = session.exchange("same-id-continuation", request, huge,
                                      verify=lambda r: rpc_refusal(r, empty=True))
            session.check("same-id-completed-request-reuse",
                          lambda: q.require(first == second, "completed same-ID requests changed or leaked context"))
    session.exchange("recovery-after-maximum-id", params("bundle"), verify=retained)

    sdk = params("notes", omit=True)
    sdk["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2999-01-01"}
    small = session.exchange("sdk-pre-dispatch-small", sdk, verify=lambda r: q.require(
        "error" in r and "2999-01-01" in r["error"]["message"], "SDK did not reject unsupported per-request version"))
    q.require("error" in small, "missing SDK error witness")
    session.exchange("sdk-pre-dispatch-maximum-id", sdk, maximal_id(sdk), verify=rpc_refusal)
    session.exchange("recovery-after-sdk-refusal", params("bundle"), verify=retained)

    escaped = params("bundle", modern=True)
    session.exchange("maximum-escaped-unicode-id", escaped, maximal_id(escaped, '\x00"\\雪😀'),
                     verify=lambda r: retained(r, True))
    for value in (-9223372036854775808, 0, 9223372036854775807):
        session.exchange("integer-id-" + str(value), params("bundle"), value, verify=retained)

    for modern, maximum in ((False, False), (True, False), (False, True)):
        label = "export-" + ("modern" if modern else "legacy") + ("-maximum-id" if maximum else "")
        path = workspace / (label + ".json")
        request = params("export", {"path": str(path)}, modern)
        response = session.exchange(label, request, maximal_id(request) if maximum else None,
                                    verify=rpc_refusal if maximum else lambda r, m=modern: success(r, m, False))
        def exported(p=path):
            q.require(p.is_file(), "completed export was lost at the final frame boundary")
            bundle = q.parse_json(p.read_bytes())
            q.require(bundle["records"] == expected, "export bytes do not contain complete retained records")
        session.check(label + "-published-complete", exported)
        if not maximum:
            payload = success(response, modern, False)["result"]
            q.require(payload["path"] == str(path) and payload["bytes"] == path.stat().st_size,
                      "export response did not describe actual published bytes")
    session.exchange("final-retained-recovery", params("bundle"), verify=retained)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "build-summary", "source-checkpoint", "reference-package",
                 "reference-tarball", "output-dir", "repo"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)),
              "all paths must be absolute")
    output = args.output_dir
    q.require(not output.exists(), "refusing to overwrite prior qualification")
    output.mkdir(parents=True, mode=0o700)
    report = {"schema": "hepta.rea.native-frame-mcp.v1", "qualified": False, "status": "OPEN",
              "scope": "Finite Linux actual STDIO frame guard; no new upstream operation qualification",
              "limits": {"final_frame_bytes": FRAME_BYTES, "request_seconds": q.REQUEST_SECONDS,
                         "eof_seconds": q.EOF_SECONDS, "line_bytes": q.MAX_WIRE_BYTES,
                         "session_received_bytes": 256 * 1024 * 1024},
              "open_requirements": ["full-operation-parity", "HTTP-and-unadmitted-input-scope",
                                    "cross-platform-lifecycle"],
              "sessions": {}, "errors": [], "source_monitors": {}}
    monitors = []
    try:
        for label, selection in (
                ("root", Selection(args.repo, output / "unused-target", output)),
                ("producer", Selection(Path(__file__).resolve().parents[1], output / "unused-target", output)),
                ("npm", AllPackageFiles(args.reference_package, output / "unused-target", output))):
            monitor = SourceMonitor(selection)
            monitor.start()
            before = selection.snapshot()
            monitors.append((label, selection, monitor, before))
            q.write_json(output / (label + "-before.json"), before)
        report["binding_before"] = check_build(args, output)
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        notes = q.elf(q.note(owner=b"FRAME_OWNER_" + b"n" * 16384 + b"\0", kind=0x1234))
        (workspace / "notes.elf").write_bytes(notes)
        apk = args.repo / "tests/fixtures/rea_apk_signature/rotation-v31.apk"
        q.require(q.file_hash(apk) == alias.FIXTURE_SHA256, "frozen APK fixture changed")
        (workspace / "rotation.apk").write_bytes(apk.read_bytes())
        report["fixtures"] = [q.identity(workspace / name) for name in ("notes.elf", "rotation.apk")]
        config = output / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
                             "hosts": {"never-connect": {"ssh_target": "never-connect-invalid",
                                       "remote_state_dir": str(output / "unused-remote"), "allow_execute": False,
                                       "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        for name, command in (("runtime", [str(args.binary), "mcp", "--runtime-config", str(config)]),
                              ("legacy-no-runtime", [str(args.binary), "mcp"])):
            state = report["sessions"][name] = {}
            client = CompressedMcp(command, workspace, {}, output / name)
            session = Session(client, state)
            try:
                state["initialize"] = client.initialize()
                q.require(state["initialize"]["result"]["protocolVersion"] == "2025-11-25",
                          "actual SDK legacy initialization changed")
                catalog = client.tools()
                state["tool_names"] = [tool["name"] for tool in catalog]
                if name == "runtime":
                    q.require(set(TOOL_NAMES.values()) <= set(state["tool_names"]), "required native tools are absent")
                    run_main(session, workspace)
                else:
                    q.require(not any(tool.startswith("rea_") for tool in state["tool_names"]),
                              "runtime-only tool leaked into legacy router")
                    request = params("bundle", omit=True)
                    session.exchange("router-error-maximum-id", request, maximal_id(request), verify=rpc_refusal)
                    session.exchange("router-error-recovery", request, verify=lambda r: q.require(
                        "error" in r or r.get("result", {}).get("isError") is True, "unknown tool unexpectedly succeeded"))
            finally:
                state["close"] = client.close()
                q.require(a.closed_normally(state["close"]), name + " process ownership did not drain normally")
                state["wire_index"] = q.artifact_reference(client.output / "wire.jsonl", output)
                state["wire_originals_verified"] = len(client.entries)
                for entry in client.entries:
                    client.original(entry)
        report["binary_after"] = q.identity(args.binary)
        q.require(report["binary_after"] == report["binding_before"]["binary"], "frozen binary changed")
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        q.require(report["reference_before"] == report["reference_after"], "frozen npm package changed")
        q.require(report["fixtures"] == [q.identity(workspace / name) for name in ("notes.elf", "rotation.apk")],
                  "independent target fixtures changed")
    except BaseException as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        for label, selection, monitor, before in monitors:
            try:
                after = selection.snapshot()
                q.write_json(output / (label + "-after.json"), after)
                if before != after:
                    report["errors"].append(label + " changed during qualification")
            except BaseException as error:
                report["errors"].append(label + " after snapshot: " + str(error))
            observation = monitor.stop()
            report["source_monitors"][label] = observation
            if observation["event_count"] or observation["errors"]:
                report["errors"].append(label + " monitor saw mutations or lost coverage")
        rows = [row for state in report["sessions"].values() for row in state.get("rows", [])]
        checks = [row for state in report["sessions"].values() for row in state.get("checks", [])]
        report["passed"] = sum(row["status"] == "PASS" for row in rows)
        report["failed"] = [row["id"] for row in rows + checks if row["status"] != "PASS"]
        report["checks"] = len(checks)
        complete = (len(rows) == 30 and len(checks) == 4 and len(report["sessions"]) == 2)
        report["finite_status"] = "PASS" if complete and not report["failed"] and not report["errors"] else "FAIL"
        report["status"] = "OPEN" if report["finite_status"] == "PASS" else "FAILED"
        receipt = q.write_json(output / "qualification.json", report)
        print(json.dumps({"qualified": False, "finite_status": report["finite_status"], "receipt": receipt,
                          "passed": report["passed"], "failed": report["failed"], "checks": len(checks),
                          "errors": report["errors"]}), flush=True)
    return 0 if report["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
