"""Actual data-only reader refusals; no native or Rust reruns."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import TRACE_HEADER
from common import BASE, document, encoded, put, read, require, sha, tree_files
from reader import read_capture

NAMES = ("input-before", "input-after", "output-after", "output-tail", "workspace-after",
         "omitted-native-case", "original-result", "actual-context", "source-owner", "module-image",
         "compile-output-tail", "original-source", "registry-archive", "native-process-pid",
         "native-process-deadline", "original-process-pid")


def copy_capture(capture, destination):
    seal = document(capture / "CAPTURE.json")
    destination.mkdir(parents=True, exist_ok=False)
    for name, info in seal["files"].items():
        raw = read(capture / name)
        require(len(raw) == info["bytes"] and sha(raw) == info["sha256"], "producer changed before physical copy")
        path = destination / name
        put(path, raw)
        path.chmod(info["mode"])
        require(path.stat().st_ino != (capture / name).stat().st_ino or path.stat().st_dev != (capture / name).stat().st_dev,
                "reader copy unexpectedly shares an inode")
    put(destination / "CAPTURE.json", read(capture / "CAPTURE.json"))
    (destination / "CAPTURE.json").chmod((capture / "CAPTURE.json").stat().st_mode & 0o777)


def mutation_data(capture):
    trace_path = "native/trace.gz"
    trace = gzip.decompress(read(capture / trace_path))
    fields = TRACE_HEADER.unpack_from(trace)
    sizes = (max(1, fields[6]) + 16, fields[7] + 16, fields[8] + 16)
    offsets = []
    at = TRACE_HEADER.size
    for size in sizes:
        offsets += [at, at + size]
        at += size * 2
    for name, offset in (("input-before", offsets[0]), ("input-after", offsets[1]),
                         ("output-after", offsets[3]), ("output-tail", offsets[3] + 32),
                         ("workspace-after", offsets[5])):
        changed = bytearray(trace)
        changed[offset] ^= 1
        yield name, trace_path, gzip.compress(bytes(changed), compresslevel=1, mtime=0)
    at, last = 0, 0
    while at < len(trace):
        last = at
        values = TRACE_HEADER.unpack_from(trace, at)
        at += TRACE_HEADER.size + 2 * (max(1, values[6]) + values[7] + values[8] + 48)
    require(at == len(trace), "control trace framing")
    yield "omitted-native-case", trace_path, gzip.compress(trace[:last], compresslevel=1, mtime=0)
    mapping = [
        ("original-result", "processes/original-replay.stdout", 8),
        ("actual-context", "processes/original-replay.stderr", 0),
        ("source-owner", "source/native/context_protocol_policy.hepta", 1),
        ("module-image", "build/modules/context-protocol-policy/module.image.bin", 0),
        ("compile-output-tail", "build/modules/context-protocol-policy/module.output.bin", -1),
        ("original-source", "source/" + BASE + "/oracle/original_policy.rs", 1),
    ]
    for name, relative, offset in mapping:
        raw = bytearray(read(capture / relative))
        raw[offset] ^= 1
        yield name, relative, bytes(raw)
    first_crate = sorted(document(capture / "registry.json")["packages"])[0]
    relative = "registry/" + first_crate + ".crate"
    raw = bytearray(read(capture / relative))
    raw[-1] ^= 1
    yield "registry-archive", relative, bytes(raw)
    for name, relative, field in (
        ("native-process-pid", "processes/native-replay.json", "pid"),
        ("native-process-deadline", "processes/native-replay.json", "timeout_seconds"),
        ("original-process-pid", "processes/original-replay.json", "pid"),
    ):
        row = document(capture / relative)
        row[field] += 1
        if field == "pid":
            row["pgid"] = row["pid"]
        yield name, relative, encoded(row)


def run(capture, output, pins_sha):
    baseline = read_capture(capture, capture / "source", pins_sha)
    baseline_files = tree_files(capture)
    output.mkdir(parents=True, exist_ok=False)
    clone = output / "temporary-reader-copy"
    copy_capture(capture, clone)
    rows = []
    seal_bytes = read(clone / "CAPTURE.json")
    for name, relative, changed in mutation_data(capture):
        original = read(clone / relative)
        mutated_path = output / "mutations" / name / "bytes.bin"
        put(mutated_path, changed)
        (clone / relative).write_bytes(changed)
        seal = json.loads(seal_bytes)
        entry = seal["files"][relative]
        entry.update(bytes=len(changed), sha256=sha(changed))
        # Rebind the container index so the semantic/source/process reader,
        # rather than only the outer file hash, must reject each mutation.
        (clone / "CAPTURE.json").write_bytes(encoded(seal))
        try:
            read_capture(clone, capture / "source", pins_sha)
        except (ValueError, KeyError, EOFError, OSError, json.JSONDecodeError) as exc:
            rows.append({"name": name, "path": relative, "original_sha256": sha(original),
                "mutated_sha256": sha(changed), "mutated_bytes": len(changed),
                "base_capture_sha256": baseline["capture_sha256"], "rebound_index_sha256": sha(encoded(seal)),
                "refusal_type": type(exc).__name__, "refusal": str(exc)})
        else:
            raise ValueError("strict reader admitted mutation " + name)
        finally:
            (clone / relative).write_bytes(original)
            (clone / "CAPTURE.json").write_bytes(seal_bytes)
    require(tuple(row["name"] for row in rows) == NAMES, "fixed reader control set")
    require(read_capture(clone, clone / "source", pins_sha) == baseline, "restored independent copy differs")
    require(tree_files(capture) == baseline_files, "reader controls modified producer capture")
    # Delete only this known temporary physical copy, after restoring and reading
    # every original byte. The actual relocated reader copies are kept separately.
    shutil.rmtree(clone)
    put(output / "report.json", {"schema": "hepta.runtime.context-protocol-reader-controls.v1",
        "pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgrp(), "rows": rows,
        "native_or_rust_executions": 0, "base_capture_sha256": baseline["capture_sha256"],
        "producer_unchanged": True, "restored_physical_copy_pass": True})
    print("CONTEXT_PROTOCOL_READER_CONTROLS_PASS", len(rows), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-pins-sha256", required=True)
    args = parser.parse_args()
    run(args.capture.absolute(), args.output.absolute(), args.source_pins_sha256)
