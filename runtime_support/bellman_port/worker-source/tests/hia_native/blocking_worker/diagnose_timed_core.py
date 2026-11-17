"""Actual old/new HIA comparison with private typed clock acknowledgements.

This is a development diagnostic. Synthetic clock words exercise numerical
continuations; actual kernel CLOCK and original Rust are separate domains.
"""
from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import time

Q = struct.Struct("<Q")
YIELD = 0xffffffe0
DEADLINE = 0xfffffdf0
ORIGINAL_SHA = "254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Capture:
    def __init__(self, path):
        path.mkdir()
        self.path = path
        self.rows = []
        self.index = {}
        self.last = {}
        self.bytes = 0
        self.unique_bytes = 0
        self.stream = gzip.GzipFile(filename=str(path / "buffers.bin.gz"), mode="wb", compresslevel=1, mtime=0)

    def blob(self, raw, kind=None):
        self.bytes += len(raw)
        # Python bytes are immutable. A complete identity/equality comparison
        # can reuse their already retained digest without hashing a multi-MiB
        # unchanged input at every private clock continuation. This retains the
        # exact full buffer, not a prefix, summary, or synthetic native result.
        if kind in self.last:
            previous, digest = self.last[kind]
            if raw is previous or raw == previous:
                return digest
        digest = sha(raw)
        if digest not in self.index:
            self.index[digest] = {"index": len(self.index), "bytes": len(raw)}
            self.stream.write(Q.pack(len(raw)))
            self.stream.write(raw)
            self.unique_bytes += len(raw)
        if kind is not None:
            self.last[kind] = (raw, digest)
        return digest

    def invoke(self, session, wire, *, case, phase):
        before_o = bytes(session._output.raw[:session.output_capacity])
        before_w = bytes(session._workspace.raw[:session.workspace_capacity])
        code, output, workspace = session.invoke_raw(wire)
        self.rows.append({"case": case, "phase": phase, "code": code, "input": self.blob(wire, "input"),
                          "before_output": self.blob(before_o, "output"), "before_workspace": self.blob(before_w, "workspace"),
                          "after_output": self.blob(output, "output"), "after_workspace": self.blob(workspace, "workspace")})
        return code, output, workspace

    def close(self):
        self.stream.close()
        (self.path / "calls.json").write_text(json.dumps(self.rows, separators=(",", ":"), sort_keys=True) + "\n")
        (self.path / "buffers.json").write_text(json.dumps(self.index, separators=(",", ":"), sort_keys=True) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--limit", type=int)
    a = p.parse_args()
    sys.path.insert(0, str(a.source_root / "scripts"))
    sys.path.insert(0, str(Path(__file__).parent / "reference"))
    from hia_native_loader import NativeModule
    from qualify_bellman import corpus, pack_graph, terminal

    def module(name):
        path = a.build / "modules" / name / "manifest.json"
        return NativeModule(path, manifest_sha256=sha(path.read_bytes()))

    old, timed, commitment = module("old-core"), module("timed-core"), module("commitment")
    graphs = list(corpus())
    patterns = list(itertools.product((-0., 0.), repeat=3))
    for i, (first, second) in enumerate(itertools.product(patterns, repeat=2)):
        graphs.append(("signed-zero-" + str(i), [[terminal(x) for x in row] + [None] * 3 for row in (first, second)], None))
    if a.limit is not None:
        graphs = graphs[:a.limit]
    capture = Capture(a.output)
    rows = []
    begin = time.monotonic()
    try:
        for case, (name, graph, declared_error) in enumerate(graphs):
            wire = pack_graph(graph)
            size = max(200, 128 + len(graph) * 72)
            with old.session(output_capacity=size + 16, workspace_capacity=size + 16) as baseline, \
                    timed.session(output_capacity=size + 16, workspace_capacity=size + 512 + 16) as current:
                ctypes.memset(baseline._output, 0xcc, baseline.output_capacity)
                old_code, old_out, old_work = capture.invoke(baseline, wire, case=case, phase="old")
                start = 1000000000000 + case * 100000000000
                init = b"HBTMIN01" + struct.pack("<7Q", case + 1, start, 1, 0, 0, 0, 0)
                init_code, init_out, initial = capture.invoke(current, init, case=case, phase="initialize")
                assert init_code == 64 and init_out[:8] == b"HBTMIR01", (name, "init", hex(init_code))
                ctypes.memset(current._output, 0xcc, current.output_capacity)
                effects = []
                while True:
                    code, output, work = capture.invoke(current, wire, case=case, phase="resume")
                    if code != YIELD:
                        break
                    assert output == bytes([0xcc]) * current.output_capacity, (name, "yield output mutated")
                    t = current.workspace_capacity - 512
                    effect = struct.unpack_from("<16Q", work, t + 256)
                    assert effect[0] == int.from_bytes(b"HBTMEF01", "little")
                    _, sequence, kind, generation, pc, index, observed_start, end, ilen, olen, extent, *reserved = effect
                    assert generation == case + 1 and observed_start == start and end == start + 30000000000
                    assert ilen == len(wire) and olen == current.output_capacity and extent == 128 + len(graph) * 72 and not any(reserved)
                    assert sequence == len(effects) + 1
                    child_code = 0
                    now = start + sequence
                    if kind == 2:
                        assert pc == 2 and index == 0
                        commitment_wire = b"HBCMT001" + bytes.fromhex(ORIGINAL_SHA) + wire
                        committed = commitment.invoke(commitment_wire, output_capacity=8388736, workspace_capacity=8404992)
                        assert committed[:8] == b"HBCMTRES" and len(committed) == 128 + Q.unpack_from(committed, 8)[0]
                        capture.rows.append({"case": case, "phase": "actual-commitment", "input": capture.blob(commitment_wire), "output": capture.blob(committed)})
                        now = 0
                    else:
                        assert kind == 1 and pc in (1, 3, 4, 5)
                    acknowledgement = b"HBTMAK01" + struct.pack("<7Q", sequence, kind, generation, now, child_code, 0, 0)
                    ctypes.memmove(ctypes.addressof(current._workspace) + t + 384, acknowledgement, 64)
                    effects.append([kind, pc, index])
                assert code == old_code and output == old_out, (name, "final differs", hex(code), hex(old_code))
                assert work[:size] == old_work[:size], (name, "numerical workspace differs")
                if code < 0xffff0000:
                    expected = [[1, 1, i] for i in range(len(graph))] + [[2, 2, 0]] + [[1, 3, i] for i in range(len(graph))] + [[1, 4, i] for i in range(len(graph))] + [[1, 5, 0]]
                    assert effects == expected, (name, "effect order")
                rows.append({"case": case, "name": name, "code": code, "effects": effects, "output_sha256": sha(output), "declared_error": declared_error})
                (a.output / "progress.json").write_text(json.dumps({"completed": len(rows), "last": name, "native_calls": len(capture.rows)}, sort_keys=True) + "\n")
        report = {"schema": "hepta.runtime.bellman-timed-core.diagnostic.v1", "status": "PASS",
                  "cases": len(rows), "native_calls": len(capture.rows), "elapsed_seconds": time.monotonic() - begin,
                  "complete_buffer_bytes": capture.bytes, "unique_buffer_bytes": capture.unique_bytes,
                  "synthetic_clock_acknowledgements": True, "actual_kernel_deadline_qualified": False,
                  "timed_commitment_qualified": False, "rust_executed": False,
                  "source_sha256": timed.metadata["source_sha256"], "image_sha256": timed.metadata["image_sha256"], "rows": rows}
        (a.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({k:v for k,v in report.items() if k != "rows"},sort_keys=True))
    finally:
        capture.close()
        old.close()
        timed.close()
        commitment.close()


if __name__ == "__main__":
    main()
