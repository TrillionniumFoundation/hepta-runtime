#!/usr/bin/env python3
"""One explicit new-version actual-file check of the callable export path."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess
import time

PIN = lambda raw: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
Q = lambda *words: struct.pack("<" + "Q" * len(words), *words)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.absolute()
    root.mkdir(parents=True, exist_ok=False)
    fixture = root / "files"
    fixture.mkdir()
    path = fixture / "sample.txt"
    before = b"alpha\nbeta\n"
    path.write_bytes(before)
    endpoint = b"HIAEP001" + Q(0, 0, 0)
    name, content = b"insert", b"prefix\n"
    record = Q(1, 1, 1, 0, 1, len(name), len(endpoint), 0, len(content)) + name + endpoint + content
    raw_path, display = bytes(path), b"sample.txt"
    body = b"HFBWT001" + Q(1, len(raw_path), len(display), 1, len(record), 1, 0) + raw_path + display + record
    frames = [b"HVCACH01" + Q(0, 0, 0, 0, 0), b"HHISTQ01" + Q(0, 0, 0, 0, 0, 0, 0), body]
    wire = b"".join(Q(len(frame)) + frame for frame in frames)
    (root / "stdin.bin").write_bytes(wire)
    (root / "before.bin").write_bytes(before)
    started = time.monotonic()
    report = {"schema": "hepta.runtime.rebuilt-batch-smoke.v1", "status": "RUNNING",
        "executable": str(args.executable.resolve()), "executable_pin": PIN(args.executable.read_bytes()),
        "source_pin": PIN(Path(__file__).read_bytes()), "cwd": str(fixture), "timeout_seconds": 60,
        "inputs": {"stdin": PIN(wire), "before": PIN(before)}, "fresh_current_original_compared": False,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False}
    process = None
    try:
        process = subprocess.run([str(args.executable.resolve())], input=wire, cwd=fixture,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        report.update(returncode=process.returncode, timed_out=False)
        (root / "stdout.bin").write_bytes(process.stdout)
        (root / "stderr.bin").write_bytes(process.stderr)
        assert process.returncode == 0, process.returncode
        replies, cursor = [], 0
        while cursor < len(process.stdout):
            assert len(process.stdout) - cursor >= 8
            size = struct.unpack_from("<Q", process.stdout, cursor)[0]
            cursor += 8
            assert size < 0xffff0000 and size <= len(process.stdout) - cursor, size
            replies.append(process.stdout[cursor:cursor + size])
            cursor += size
        assert len(replies) == 3 and replies[2][:8] == b"HFBWR001"
        kind, size, zero = struct.unpack_from("<3Q", replies[2], 8)
        assert kind == 0 and zero == 0 and size == len(replies[2]) - 32, replies[2]
        assert path.read_bytes() == content + before
        report["status"] = "PASS"
        report["body_reply"] = PIN(replies[2])
    except subprocess.TimeoutExpired as error:
        report.update(status="FAIL", timed_out=True, error=repr(error))
        (root / "stdout.bin").write_bytes(error.stdout or b"")
        (root / "stderr.bin").write_bytes(error.stderr or b"")
        raise
    except BaseException as error:
        report.update(status="FAIL", error=repr(error))
        raise
    finally:
        (root / "after.bin").write_bytes(path.read_bytes())
        report["elapsed_seconds"] = time.monotonic() - started
        report["artifacts"] = {name: PIN((root / name).read_bytes()) for name in
            ("stdin.bin", "stdout.bin", "stderr.bin", "before.bin", "after.bin") if (root / name).exists()}
        (root / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
