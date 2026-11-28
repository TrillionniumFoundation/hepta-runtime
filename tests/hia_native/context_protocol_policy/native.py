"""Mechanical owned-buffer observer. No Rust, parser fallback or retry."""
from __future__ import annotations

import argparse
import ctypes
import gzip
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import calls, expected, initial_output, initial_workspace, TRACE_HEADER, NO_SEMANTIC
from common import BASE, encoded, packet, put, read, require, sha, source_evidence


def run(root, manifest, destination, pins_sha):
    source_evidence(root, pins_sha)
    sys.path.insert(0, str(root / "scripts"))
    from hia_native_loader import NativeModule
    destination.mkdir(parents=True, exist_ok=False)
    rows, sessions = [], {}
    with NativeModule(manifest, manifest_sha256=sha(read(manifest))) as module, \
         (destination / "semantic-output.bin").open("xb") as semantic, \
         (destination / "trace.gz").open("xb") as compressed, \
         gzip.GzipFile(filename="", fileobj=compressed, mode="wb", compresslevel=1, mtime=0) as trace:
        for index, call in enumerate(calls()):
            require(len(call.wire) <= module.metadata["input_capacity"], "input profile")
            if call.session not in sessions:
                before_output = initial_output(call.session, call.output_capacity)
                before_work = initial_workspace(call.session, call.workspace_capacity)
                output = ctypes.create_string_buffer(before_output, len(before_output))
                work = ctypes.create_string_buffer(before_work, len(before_work))
                sessions[call.session] = (output, work, 0, call.output_capacity, call.workspace_capacity)
            output, work, local_call, output_capacity, workspace_capacity = sessions[call.session]
            require((output_capacity, workspace_capacity) == (call.output_capacity, call.workspace_capacity), "session capacity changed")
            input_raw = (call.wire or b"\0") + b"\xd3" * 16
            source = ctypes.create_string_buffer(input_raw, len(input_raw))
            before = (source.raw, output.raw, work.raw)
            with module._lock:
                require(sha(read(module.source_path)) == module.metadata["source_sha256"], "source changed before actual entry")
                result = module._entry(source, len(call.wire), output, output_capacity, work, workspace_capacity)
            after = (source.raw, output.raw, work.raw)
            trace.write(TRACE_HEADER.pack(b"HCPTRC01", index, call.semantic, call.session, local_call,
                                         result, len(call.wire), output_capacity, workspace_capacity, 16, 16, 16, 0))
            for a, b in zip(before, after):
                trace.write(a)
                trace.write(b)
            # Keep the complete failed call before checking any observation.
            trace.flush()
            row = {"index": index, "name": call.name, "session": call.session, "local_call": local_call,
                   "semantic": call.semantic, "code": result, "input_bytes": len(call.wire),
                   "output_capacity": output_capacity, "workspace_capacity": workspace_capacity}
            rows.append(row)
            code, payload = expected(call.wire, output_capacity)
            require(result == code, "native return differs: " + call.name)
            require(after[0] == before[0] and after[2] == before[2], "input/workspace changed: " + call.name)
            wanted = before[1] if payload is None else payload + before[1][32:]
            require(after[1] == wanted, "complete output differs: " + call.name)
            if call.semantic != NO_SEMANTIC:
                semantic.write(packet(after[1][:32]))
            sessions[call.session] = (output, work, local_call + 1, output_capacity, workspace_capacity)
    source_evidence(root, pins_sha)
    put(destination / "report.json", {"schema": "hepta.runtime.context-protocol-native.v1",
        "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(),
        "manifest_sha256": sha(read(manifest)), "source_pins_sha256": pins_sha,
        "calls": rows, "native_calls": len(rows), "semantic_cases": sum(r["semantic"] != NO_SEMANTIC for r in rows),
        "complete_buffers": True, "semantic_fallback": False, "automatic_retries": 0})
    print("CONTEXT_PROTOCOL_NATIVE_PASS", len(rows), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-pins-sha256", required=True)
    args = parser.parse_args()
    run(args.source_root.resolve(), args.manifest.resolve(), args.output.absolute(), args.source_pins_sha256)
