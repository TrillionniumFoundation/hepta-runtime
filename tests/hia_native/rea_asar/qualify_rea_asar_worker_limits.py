# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise native ASAR on inherited descriptors under the original worker limits.

This is an explicit Python qualification adapter, not the production worker.
HIA owns all archive parsing and cryptography; the adapter only delivers the
typed request, pread/fstat completions and complete native response.
"""
from pathlib import Path
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import time

from qualify_rea_asar_differential import archive
from rea_asar_native_transport import AsarModule, request

ORIGINAL_WORKER_SHA256 = "003462046dd35f014aec21f772f277c62d3cd73fe8982ec196b0573c225e59a1"


def frozen_limits():
    return [(resource.RLIMIT_AS, 768 * 1024 * 1024),
            (resource.RLIMIT_CPU, 12), (resource.RLIMIT_NOFILE, 64),
            (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 4 * 1024 * 1024)]


def child(args):
    for kind, allowed in frozen_limits():
        resource.setrlimit(kind, (allowed, allowed))
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    assert parent != 1 and libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0
    assert os.getppid() == parent
    observed_limits = {str(kind): list(resource.getrlimit(kind)) for kind, _ in frozen_limits()}
    assert all(observed_limits[str(kind)] == [allowed, allowed] for kind, allowed in frozen_limits())
    print(json.dumps({"event": "limits-applied", "limits": observed_limits,
        "parent_pid": parent, "pid": os.getpid()}, sort_keys=True), flush=True)
    typed = json.loads(args.child_request)
    fd = fcntl.fcntl(0, fcntl.F_DUPFD_CLOEXEC, 3)
    assert stat.S_ISREG(os.fstat(fd).st_mode)
    assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    module = AsarModule(args.manifest, args.source)
    try:
        actual = module.invoke(request(fd, **typed), fd)
        received = ({"ok": True, "value": json.loads(actual["payload"])}
                    if actual["status"] == 0 else {"ok": False, "error": actual["payload"]})
        used = resource.getrusage(resource.RUSAGE_SELF)
        print(json.dumps({"event": "complete", "response": received,
            "native_calls": actual["native_calls"], "effects": actual["effects"],
            "native_cpu_seconds": actual["native_cpu_seconds"],
            "native_wall_seconds": actual["native_wall_seconds"],
            "process_user_seconds": used.ru_utime, "process_system_seconds": used.ru_stime,
            "maximum_resident_kib": used.ru_maxrss}, sort_keys=True), flush=True)
    finally:
        module.close()
        os.close(fd)


def zero_digest(size):
    digest = hashlib.sha256()
    block = bytes(65536)
    while size:
        chunk = min(size, len(block))
        digest.update(block[:chunk])
        size -= chunk
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    for name in ("source", "manifest"):
        ap.add_argument("--" + name, required=True, type=Path)
    for name in ("oracle", "baseline-limits", "output", "fixtures-from"):
        ap.add_argument("--" + name, type=Path)
    ap.add_argument("--child-request")
    ap.add_argument("--reference-entry", type=Path)
    args = ap.parse_args()
    if args.reference_entry is not None:
        for kind, allowed in frozen_limits():
            resource.setrlimit(kind, (allowed, allowed))
        os.execv(str(args.reference_entry), [str(args.reference_entry)])
    if args.child_request is not None:
        child(args)
        return
    assert args.oracle and args.baseline_limits and args.output
    original_worker = args.source / "src/mcp/rea_asar_worker.rs"
    assert hashlib.sha256(original_worker.read_bytes()).hexdigest() == ORIGINAL_WORKER_SHA256
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    for name in ("qualify_rea_asar_worker_limits.py", "qualify_rea_asar_differential.py", "rea_asar_native_transport.py"):
        (out / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    fixtures = out / "fixtures"
    fixtures.mkdir(mode=0o700)
    cases = [json.loads((args.baseline_limits / "cases.json").read_bytes())[9]]
    fixture_specs = ((64 << 20, 65536), (64 << 20, 336), (200000, 1))
    if args.fixtures_from is not None:
        cases = json.loads((args.fixtures_from / "cases.json").read_bytes())
        assert len(cases) == 4
        fixture_specs = ()
    for ordinal, (size, block_size) in enumerate(fixture_specs):
        whole, remainder = divmod(size, block_size)
        blocks = [zero_digest(block_size)] * whole
        if remainder:
            blocks.append(zero_digest(remainder))
        assert len(blocks) <= 200000
        header = {"files": {"member": {"offset": "0", "size": size,
            "integrity": {"algorithm": "SHA256", "hash": zero_digest(size),
                "blockSize": block_size, "blocks": blocks}}}}
        raw = archive(header)
        assert len(raw) <= (16 << 20) + 8
        path = fixtures / f"integrity-{ordinal}.asar"
        with path.open("xb") as stream:
            stream.write(raw)
            stream.truncate(len(raw) + size)
        path.chmod(0o400)
        cases.append({"label": f"whole-member-and-blocks/{size}/{block_size}/{len(blocks)}",
            "path": str(path), "request": {"operation": "read", "offset": 0,
                "length": 1, "member": "member", "require_complete": False}})
    (out / "cases.json").write_text(json.dumps(cases, sort_keys=True, indent=2) + "\n")
    pinned = [args.manifest, args.source / "native/rea_asar_parser.hepta", args.oracle, original_worker,
              *(Path(row["path"]) for row in cases)]
    pins = {str(path): {"bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in pinned}
    (out / "source-pins.json").write_text(json.dumps(pins, sort_keys=True, indent=2) + "\n")
    rows = []
    for ordinal, case in enumerate(cases):
        reference_argv = [sys.executable, "-B", str(out / "qualify_rea_asar_worker_limits.py"),
            "--source", str(args.source), "--manifest", str(args.manifest),
            "--reference-entry", str(args.oracle)]
        (out / f"reference-intent-{ordinal}.json").write_text(json.dumps({
            "argv": reference_argv, "wall_seconds": 20,
            "limits": {str(kind): [allowed, allowed] for kind, allowed in frozen_limits()},
            "input": case}, sort_keys=True, indent=2) + "\n")
        reference_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        reference_started = time.monotonic()
        reference_timeout = False
        reference = subprocess.Popen(reference_argv, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            reference_stdout, reference_stderr = reference.communicate(
                (json.dumps(case) + "\n").encode(), timeout=20)
        except subprocess.TimeoutExpired:
            reference_timeout = True
            os.killpg(reference.pid, signal.SIGKILL)
            reference_stdout, reference_stderr = reference.communicate(timeout=10)
        reference_seconds = time.monotonic() - reference_started
        reference_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        (out / f"reference-{ordinal}.stdout").write_bytes(reference_stdout)
        (out / f"reference-{ordinal}.stderr").write_bytes(reference_stderr)
        reference_ok = reference.returncode == 0 and not reference_stderr and not reference_timeout
        expected = json.loads(reference_stdout) if reference_ok else None
        reference_ok = reference_ok and expected.get("ok") is True
        reference_row = {"returncode": reference.returncode, "wall_timeout": reference_timeout,
            "seconds": reference_seconds, "passed": reference_ok,
            "child_user_seconds": reference_after.ru_utime - reference_before.ru_utime,
            "child_system_seconds": reference_after.ru_stime - reference_before.ru_stime,
            "stdout_bytes": len(reference_stdout), "stderr_bytes": len(reference_stderr)}
        (out / f"reference-{ordinal}.json").write_text(
            json.dumps(reference_row, sort_keys=True, indent=2) + "\n")
        argv = [sys.executable, "-B", str(out / "qualify_rea_asar_worker_limits.py"),
            "--source", str(args.source), "--manifest", str(args.manifest),
            "--child-request", json.dumps(case["request"], separators=(",", ":"))]
        (out / f"intent-{ordinal}.json").write_text(json.dumps({"argv": argv, "stdin": case["path"],
            "wall_seconds": 20, "cpu_seconds": 12, "memory_bytes": 768 << 20,
            "descriptor_limit": 64, "file_output_bytes": 4 << 20,
            "qualification_adapter": "Python mechanical native-image caller; not production worker"},
            sort_keys=True, indent=2) + "\n")
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.monotonic()
        timed_out = False
        with Path(case["path"]).open("rb") as source:
            process = subprocess.Popen(argv, cwd=out, stdin=source, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C", LANG="C", PYTHONDONTWRITEBYTECODE="1"),
                start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=10)
        elapsed = time.monotonic() - start
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        (out / f"native-{ordinal}.stdout").write_bytes(stdout)
        (out / f"native-{ordinal}.stderr").write_bytes(stderr)
        observations = [json.loads(line) for line in stdout.splitlines()]
        limits = next((row for row in observations if row.get("event") == "limits-applied"), None)
        result = next((row for row in observations if row.get("event") == "complete"), None)
        equal = reference_ok and result is not None and result["response"] == expected
        passed = reference_ok and process.returncode == 0 and not timed_out and not stderr and limits is not None and equal
        row = {"case": case, "passed": passed, "returncode": process.returncode,
            "wall_timeout": timed_out, "seconds": elapsed, "full_response_equal": equal,
            "child_user_seconds": after.ru_utime - before.ru_utime,
            "child_system_seconds": after.ru_stime - before.ru_stime,
            "limits_observation": limits, "complete_observation": result,
            "reference_observation": reference_row,
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
        rows.append(row)
        (out / f"comparison-{ordinal}.json").write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
        print(json.dumps({k: v for k, v in row.items() if k != "complete_observation"}, sort_keys=True), flush=True)
    for name, pin in pins.items():
        raw = Path(name).read_bytes()
        assert len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"]
    report = {"status": "PASS" if all(row["passed"] for row in rows) else "FAIL",
        "cases": len(rows), "passed": sum(row["passed"] for row in rows),
        "original_worker_resource_limits_unchanged": True, "original_full_gate_replaced": False,
        "production_worker_qualified": False, "seccomp_qualified": False,
        "all_source_and_fixture_bytes_stable": True, "rows": rows}
    (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, sort_keys=True), flush=True)
    assert report["status"] == "PASS"


if __name__ == "__main__":
    main()
