"""Replay the unchanged serial domain through real native asynchronous owners.

This fixture only translates create/await/release framing. Every owner decision
and filesystem effect remains inside the manifest-pinned native executable.
"""
from pathlib import Path
import hashlib
import gzip
import json
import os
import runpy
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import effect_fence_test_support as base
import fence_async_support as asynchronous

TRANSPORT_COUNTS = {"processes": 0, "requests": 0, "responses": 0, "closed_processes": 0}
TRANSPORT_ROWS = []
asynchronous.COUNTS = TRANSPORT_COUNTS
asynchronous.ROWS = TRANSPORT_ROWS


def executable():
    manifest = Path(os.environ["HIA_FENCE_ASYNC_MANIFEST"]).resolve(strict=True)
    metadata = json.loads(manifest.read_bytes())
    path = manifest.parent / metadata["executable"]
    identity = hashlib.sha256(path.read_bytes()).hexdigest()
    if identity != metadata["elf_sha256"]:
        raise AssertionError("asynchronous native owner differs")
    return path, identity, "native-hia"


class SerialAdapter:
    def __init__(self, case, state, env, *, close_stderr=False):
        self.native = asynchronous.Session(case, state, env, close_stderr=close_stderr)
        self.case, self.process, self.pending, self.permit = case, self.native.process, None, 0
        self.operation = 0
        base.COUNTS["processes"] += 1

    def send(self, operation, host="", key=None):
        if self.pending is not None:
            raise AssertionError("serial owner fixture frame overlaps")
        host = host.encode() if isinstance(host, str) else host
        key = key.encode() if isinstance(key, str) else key
        body = b"" if key is None else key
        self.pending = b"HFFCMD01" + struct.pack("<4Q", operation, int(key is not None), len(host), len(body)) + host + body
        self.operation = operation
        if operation == 1:
            if self.permit:
                raise AssertionError("duplicate serial fixture permit")
            future = self.native.create()
            self.native.send(6, future)
        elif operation in (2, 3):
            if not self.permit:
                raise AssertionError("serial fixture permit missing")
            future = self.native.create(permit=self.permit, method=operation, host=host, key=key)
            self.native.send(6, future)
        elif operation == 4:
            if not self.permit:
                raise AssertionError("serial fixture permit missing")
            self.native.send(5, self.permit)
        else:
            raise AssertionError("serial fixture operation differs")
        base.COUNTS["requests"] += 1

    def receive(self, timeout=45):
        result = self.native.receive(timeout=timeout)
        if result[0] != 0:
            raise AssertionError(("native capability transport refused", result))
        if self.operation == 4:
            if result != (0, 0, self.permit, 0, 0, 0, 0):
                raise AssertionError("native release result differs")
            self.permit = 0
            response = (0, 0, 0, 0)
        else:
            if self.operation == 1 and result[3] == 0:
                if result[2] == 0:
                    raise AssertionError("successful acquisition lacks a private permit")
                self.permit = result[2]
            response = result[3:]
        wire = b"HFFRES01" + struct.pack("<4Q", *response)
        base.ROWS.append({"case": self.case, "ordinal": len(base.ROWS), "input_hex": self.pending.hex(),
                          "output_hex": wire.hex(), "code": response[0], "errno": response[1]})
        self.pending = None
        base.COUNTS["responses"] += 1
        return response

    def call(self, operation, host="", key=None):
        self.send(operation, host, key)
        return self.receive()

    def close(self):
        # The inherited close path records the actual owned process exit in base.
        self.native.close()


if __name__ == "__main__":
    base.Session = SerialAdapter
    base.executable = executable
    try:
        runpy.run_path(str(Path(__file__).with_name("test_fence_owner.py")), run_name="__main__")
    finally:
        folder = Path(os.environ["HIA_FENCE_CORPUS_DIR"])
        folder.mkdir(parents=True, exist_ok=True)
        raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in TRANSPORT_ROWS)
        packed = gzip.compress(raw, mtime=0)
        (folder / "async-transport.jsonl.gz").write_bytes(packed)
        report = {"schema": "hepta.effect-fence.async-serial-framing.v1",
                  "semantic_counts": base.COUNTS, "transport_counts": TRANSPORT_COUNTS,
                  "native_processes_closed": base.COUNTS["closed_processes"],
                  "native_transport_rows": len(TRANSPORT_ROWS),
                  "transport_raw_bytes": len(raw), "transport_raw_sha256": hashlib.sha256(raw).hexdigest(),
                  "transport_gzip_bytes": len(packed), "transport_gzip_sha256": hashlib.sha256(packed).hexdigest(),
                  "semantic_source_unchanged": hashlib.sha256(Path(__file__).with_name("test_fence_owner.py").read_bytes()).hexdigest()
                      == "042f1eb7a190cf8b78128983b4551e11d94fa26262ce53b386636117e9e7387e",
                  "framing_only": True, "whole_runtime_replaced": False,
                  "sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
                      Path(__file__), Path(__file__).with_name("fence_async_support.py"),
                      Path(__file__).with_name("effect_fence_test_support.py"))}}
        (folder / "async-framing.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
