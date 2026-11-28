#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare real HIA event bytes with the pinned original Serde serializer."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location("jobs_audit_event_loader", ROOT / "scripts/hia_native_loader.py")
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    manifest_hash = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    native = loader.NativeModule(args.manifest, manifest_sha256=manifest_hash)
    rng = random.Random(0x4849414155444954)
    texts = ["", "host", "/tmp/audit target", "\"\\/\b\t\n\r\f",
             "".join(map(chr, range(32))), "你好/é/💡", "\u2028\u2029", "x" * 4096]
    alphabet = list("aZ0/\\\" \n\t") + [chr(i) for i in range(32)] + ["é", "汉", "💡", "\u2028"]
    texts += ["".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 80))) for _ in range(80)]
    times = [0, 1, 9, 10, 99, 100, 2**32 - 1, 2**53 - 1, 2**53 + 1, 2**63 - 1, 2**64 - 1]
    cases = [{"host": h, "subject": rng.choice(texts), "timestamp": str(t)}
             for h in texts for t in times]
    cases += [{"host": h, "subject": rng.choice(texts)} for h in texts]
    cases += [{"host": "h", "subject": "p", "timestamp": str(t)}
              for t in [2**64, 2**64 + 1, 2**127, 2**128 - 1]]
    original_input = "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases).encode()
    (args.output / "reference.stdin.jsonl").write_bytes(original_input)
    original = subprocess.run([str(args.reference.resolve(strict=True))], input=original_input,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    (args.output / "reference.stdout.jsonl").write_bytes(original.stdout)
    (args.output / "reference.stderr").write_bytes(original.stderr)
    if original.returncode != 0:
        raise RuntimeError("original serializer failed: " + original.stderr.decode(errors="replace"))
    replies = [json.loads(line) for line in original.stdout.splitlines()]
    if len(replies) != len(cases):
        raise RuntimeError("original case inventory changed")
    counts = {"typed_events": 0, "original_clock_events": 0, "timestamp_refusals": 0,
              "capacity_refusals": 0, "abi_refusals": 0}
    evidence_path = args.output / "complete-native-frames.jsonl.gz"
    with gzip.open(evidence_path, "wt", encoding="utf-8") as evidence:
        def check(label, wire, capacity, expected, category):
            code, output, workspace = native.invoke_raw(wire, output_capacity=capacity,
                workspace_capacity=64, output_fill=0xc7, workspace_fill=0x93)
            row = {"label": label, "input_hex": wire.hex(), "return": code,
                   "output_hex": output.hex(), "workspace_hex": workspace.hex(),
                   "expected_hex": expected.hex() if isinstance(expected, bytes) else None,
                   "expected_return": len(expected) if isinstance(expected, bytes) else expected}
            evidence.write(json.dumps(row, sort_keys=True) + "\n")
            if workspace != b"\x93" * 64:
                raise AssertionError((label, "unused workspace changed"))
            if isinstance(expected, bytes):
                if code != len(expected) or output != expected + b"\xc7" * (capacity-len(expected)):
                    raise AssertionError((label, "complete result or output tail differs", code))
            elif code != expected or output != b"\xc7" * capacity:
                raise AssertionError((label, "refusal altered mutable storage", code))
            counts[category] += 1
        wires = []
        for index, (case, result) in enumerate(zip(cases, replies, strict=True)):
            timestamp = int(case["timestamp"]) if "timestamp" in case else json.loads(result["line"])["at_unix_ms"]
            host, subject = case["host"].encode(), case["subject"].encode()
            wire = struct.pack("<8Q", int.from_bytes(b"HJAERQ01", "little"), timestamp & (2**64-1),
                               timestamp >> 64, len(host), len(subject), 5, 0, 0) + host + subject + b"write"
            if "timestamp_error" in result:
                check(str(index), wire, 256, 0xffffffff, "timestamp_refusals")
                continue
            line = result["line"].encode()
            expected = struct.pack("<4Q", int.from_bytes(b"HRCFGM01", "little"), 0, 0, len(line)) + line
            check(str(index), wire, len(expected)+71, expected,
                  "typed_events" if "timestamp" in case else "original_clock_events")
            if index < 12:
                wires.append((wire, expected))
        wire, expected = wires[0]
        for capacity in range(len(expected)):
            check("short:"+str(capacity), wire, capacity, 0xfffffffe, "capacity_refusals")
        for length in range(len(wire)):
            check("truncated:"+str(length), wire[:length], 256, 0xffffffff, "abi_refusals")
        for offset in [0, 16, 24, 32, 40, 48, 56]:
            for value in [1, 2**64-1]:
                bad = bytearray(wire);struct.pack_into("<Q", bad, offset, value)
                check("header:"+str(offset)+":"+str(value), bytes(bad), 256, 0xffffffff, "abi_refusals")
        for raw in [b"\x80", b"\xc0\x80", b"\xe0\x80\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80", b"\xc2", b"\xe2\x82"]:
            for field in [0, 1]:
                host, subject = (raw, b"p") if field == 0 else (b"h", raw)
                bad = struct.pack("<8Q", int.from_bytes(b"HJAERQ01", "little"), 1, 0, len(host), len(subject), 5, 0, 0)+host+subject+b"write"
                check("utf8:"+str(field)+":"+raw.hex(), bad, 256, 0xffffffff, "abi_refusals")
    native.close()
    report = {"schema": "hepta.runtime.jobs-audit-event.qualification.v1", "passed": True,
              "counts": counts, "manifest_sha256": manifest_hash,
              "reference_sha256": hashlib.sha256(args.reference.read_bytes()).hexdigest(),
              "source_sha256": hashlib.sha256((ROOT / "native/jobs_audit_event.hepta").read_bytes()).hexdigest(),
              "complete_frames_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
              "original_returncode": original.returncode, "original_stderr_bytes": len(original.stderr),
              "append_io_qualified": False, "warm_namespace_qualified": False, "public_route_qualified": False}
    (args.output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
