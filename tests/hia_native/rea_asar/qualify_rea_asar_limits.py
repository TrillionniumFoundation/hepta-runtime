# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Original ASAR size, inventory, integrity and descriptor-change boundaries."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time
import traceback

from qualify_rea_asar_differential import archive, integrity
from rea_asar_native_transport import AsarModule, request


def main():
    ap = argparse.ArgumentParser()
    for name in ("source", "manifest", "oracle", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    fixtures, events = out / "fixtures", out / "native-events"
    fixtures.mkdir(mode=0o700)
    events.mkdir(mode=0o700)
    for name in ("qualify_rea_asar_limits.py", "qualify_rea_asar_differential.py", "rea_asar_native_transport.py"):
        (out / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    pins = {str(p): {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in (args.manifest, args.oracle, args.source / "native/rea_asar_parser.hepta")}
    (out / "source-pins.json").write_text(json.dumps(pins, sort_keys=True, indent=2) + "\n")
    cases = []

    def admit(label, data, typed=None, sparse=0):
        path = fixtures / f"{len(cases):03}.asar"
        with path.open("xb") as stream:
            stream.write(data)
            if sparse:
                stream.truncate(len(data) + sparse)
        path.chmod(0o400)
        typed = typed or {"operation": "index", "offset": 0, "limit": 1}
        cases.append({"label": label, "path": str(path), "request": typed})

    empty = b'{"files":{}}'
    for size in (8 * 1024 * 1024 + 4, 16 * 1024 * 1024 - 8, 16 * 1024 * 1024 - 4):
        admit(f"original-header-byte-boundary/{size}",
            archive(empty + b" " * (size - len(empty))))
    for count, prefix in ((50000, ""), (50001, ""), (50000, "x" * 270)):
        files = {prefix + f"{i:05}": {"offset": "0", "size": 0} for i in range(count)}
        admit(f"full-inventory/{count}/common-prefix/{len(prefix)}",
            archive({"files": files}))
    for count in (200000, 200001):
        blocks = ["0" * 64] * count
        header = {"files": {"member": {"size": count, "unpacked": True,
            "integrity": {"algorithm": "SHA256", "hash": "0" * 64,
            "blockSize": 1, "blocks": blocks}}}}
        admit(f"total-integrity-blocks/{count}", archive(header))
    parts = {str(i): {"size": 100001, "unpacked": True,
        "integrity": {"algorithm": "SHA256", "hash": "0" * 64,
        "blockSize": 1, "blocks": ["0" * 64] * 100001}} for i in range(2)}
    admit("cross-member-total-integrity-blocks/200002", archive({"files": parts}))
    for size in (64 * 1024 * 1024, 64 * 1024 * 1024 + 1):
        header = archive({"files": {"member": {"offset": "0", "size": size}}})
        admit(f"whole-member-verification/{size}", header, sparse=size,
            typed={"operation": "read", "offset": 0, "length": 1,
                "member": "member", "require_complete": False})
    full = bytes(range(256)) * 4096
    header = {"files": {"member": {"offset": "0", "size": len(full),
        "integrity": integrity(full, 65536)}}}
    admit("complete-source-one-MiB", archive(header, full),
        typed={"operation": "read", "offset": 0, "length": len(full),
            "member": "member", "require_complete": True})
    (out / "cases.json").write_text(json.dumps(cases, sort_keys=True, indent=2) + "\n")
    module = AsarModule(args.manifest, args.source)
    oracle_err = (out / "oracle.stderr").open("xb")
    oracle = subprocess.Popen([str(args.oracle)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=oracle_err, text=True, bufsize=1)
    started = time.monotonic()
    rows, differences, native_calls = [], 0, 0
    try:
        for ordinal, case in enumerate(cases):
            fd = os.open(case["path"], os.O_RDONLY)
            try:
                oracle.stdin.write(json.dumps(case) + "\n")
                oracle.stdin.flush()
                expected = json.loads(oracle.stdout.readline())
                wall = time.monotonic()
                with (events / f"case-{ordinal:03}.jsonl").open("x") as stream:
                    actual = module.invoke(request(fd, **case["request"]), fd, stream)
                seconds = time.monotonic() - wall
                received = ({"ok": True, "value": json.loads(actual["payload"])}
                    if actual["status"] == 0 else {"ok": False, "error": actual["payload"]})
                equal = expected == received
                differences += not equal
                native_calls += actual["native_calls"]
                row = {"case": case, "reference": expected, "native": received,
                    "equal": equal, "native_calls": actual["native_calls"],
                    "native_cpu_seconds": actual["native_cpu_seconds"],
                    "native_wall_seconds": actual["native_wall_seconds"],
                    "driver_seconds_including_full_evidence": seconds}
                (out / f"comparison-{ordinal:03}.json").write_text(json.dumps(row, sort_keys=True) + "\n")
                rows.append({key: value for key, value in row.items() if key not in ("reference", "native")})
                print(json.dumps(rows[-1], sort_keys=True), flush=True)
            finally:
                os.close(fd)
        oracle.stdin.close()
        assert oracle.wait(timeout=30) == 0

        mutation_path = fixtures / "actual-mutation.asar"
        mutation_path.write_bytes(archive({"files": {}}))
        fd = os.open(mutation_path, os.O_RDONLY)
        mutation = []
        try:
            def before_effect(effect, _workspace):
                if effect[2] == 2:
                    before = os.stat(mutation_path)
                    os.utime(mutation_path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
                    after = os.stat(mutation_path)
                    mutation.append({"before_mtime_ns": before.st_mtime_ns,
                        "after_mtime_ns": after.st_mtime_ns,
                        "same_device_inode": (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)})
            with (events / "actual-mutation.jsonl").open("x") as stream:
                actual = module.invoke(request(fd), fd, stream, before_effect)
            assert mutation and mutation[0]["same_device_inode"]
            assert actual["status"] == 1 and actual["payload"] == "REA inspection denied: admitted artifact changed during read"
            native_calls += actual["native_calls"]
            (out / "actual-mutation.json").write_text(json.dumps({"mutation": mutation, "native": actual}, sort_keys=True) + "\n")
        finally:
            os.close(fd)
        for name, pin in pins.items():
            raw = Path(name).read_bytes()
            assert len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"]
        report = {"status": "PASS" if differences == 0 else "FAIL",
            "full_comparisons": len(rows), "differences": differences,
            "actual_same_descriptor_mutations": len(mutation), "native_calls": native_calls,
            "seconds": time.monotonic() - started, "rows": rows,
            "original_limits_unchanged": True, "public_worker_deadline_qualified": False,
            "public_route_qualified": False}
        (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True), flush=True)
        assert differences == 0
    except BaseException as error:
        (out / "failure.json").write_text(json.dumps({"status": "FAIL", "completed": rows,
            "differences": differences, "error": repr(error), "traceback": traceback.format_exc()},
            sort_keys=True, indent=2) + "\n")
        raise
    finally:
        if oracle.poll() is None:
            oracle.terminate()
            oracle.wait(timeout=30)
        oracle_err.close()
        module.close()


if __name__ == "__main__":
    main()
