"""Exact paired original/native kernel races, syscall errors and scan deadline."""
from pathlib import Path
import fcntl
import hashlib
import gzip
import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import effect_fence_test_support as base
import fence_async_support as asynchronous
import effect_fence_async_serial_adapter as framing
from fence_kernel_supervisor import CASES

EVIDENCE = Path(os.environ["HIA_FENCE_KERNEL_CORPUS_DIR"]).resolve()
EVIDENCE.mkdir(parents=True, exist_ok=True)
BACKEND = os.environ["HIA_FENCE_KERNEL_BACKEND"]
if BACKEND not in ("native", "original"):
    raise AssertionError("kernel comparison backend must be explicit")
REPORTS = []


def executable():
    if BACKEND == "native":
        path, identity, backend = framing.executable()
        manifest = json.loads(Path(os.environ["HIA_FENCE_ASYNC_MANIFEST"]).read_bytes())
        if manifest["worker_limit"] != 512:
            raise AssertionError("production worker limit differs")
        return path, identity, backend
    return base.executable()


def start(session, case, state, env):
    session.executable, session.identity, session.backend = executable()
    session.case, session.pending = case, None
    session.report_path = EVIDENCE / (case + ".json")
    if session.report_path.exists():
        raise AssertionError("kernel evidence already exists")
    command = [sys.executable, "-I", "-B", str(Path(__file__).with_name("fence_kernel_supervisor.py")),
        "--binary", str(session.executable), "--sha256", session.identity,
        "--case", case, "--fixture", str(Path(state).parent),
        "--report", str(session.report_path), "--state-root", str(state)]
    session.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env)


class OriginalSession(base.Session):
    def __init__(self, case, state, env, *, close_stderr=False):
        if close_stderr:
            raise AssertionError("paired kernel cases preserve stderr")
        start(self, case, state, env)
        base.COUNTS["processes"] += 1


class NativeSession(asynchronous.Session):
    def __init__(self, case, state, env, *, close_stderr=False):
        if close_stderr:
            raise AssertionError("paired kernel cases preserve stderr")
        start(self, case, state, env)
        asynchronous.COUNTS["processes"] += 1


if BACKEND == "native":
    framing.asynchronous.Session = NativeSession
    base.Session = framing.SerialAdapter
else:
    base.Session = OriginalSession


def exclusive(file):
    try:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    fcntl.flock(file, fcntl.LOCK_UN)
    return True


class KernelTests(unittest.TestCase):
    def exercise(self, case, code, error=0, *, query=False):
        with self.subTest(case=case), base.Fixture("v11" if query else "v4") as fixture:
            if query:
                fixture.job()
            # This independent open description remains bound to the original
            # lock inode even when the test replaces its pathname.
            with open(fixture.authority / ".owner.lock", "rb") as lock:
                session = fixture.session(case)
                if query:
                    self.assertEqual(session.call(1), (0, 0, 7, 1))
                    self.assertFalse(exclusive(lock))
                    self.assertEqual(session.call(2, "local", "fresh"), (code, error, 7, 1))
                    self.assertFalse(exclusive(lock))
                    self.assertEqual(session.call(4), (0, 0, 0, 0))
                else:
                    self.assertEqual(session.call(1), (code, error, 7 if code == 0 else 0, 0))
                    if code == 0:
                        self.assertFalse(exclusive(lock))
                        self.assertEqual(session.call(4), (0, 0, 0, 0))
                self.assertTrue(exclusive(lock))
                session.close()
                native = session.native if BACKEND == "native" else session
                raw = native.report_path.read_bytes()
                report = json.loads(raw)
                self.assertEqual(report["status"], "PASS")
                self.assertEqual(report["case"], case)
                self.assertEqual(report["executable_sha256"], native.identity)
                self.assertEqual(report["fault_count"], 1)
                self.assertTrue(report["all_owned_tasks_reaped"])
                self.assertTrue(all(code == 0 for code in report["exit_statuses"].values()))
                self.assertEqual(report["supervisor_sha256"], hashlib.sha256(
                    Path(__file__).with_name("fence_kernel_supervisor.py").read_bytes()).hexdigest())
                REPORTS.append({"case": case, "path": native.report_path.name,
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})

    def test_01_descriptor_and_path_rebinding(self):
        for case, code in (("owner_replace", 16), ("owner_touch", 16), ("lock_replace", 24),
                           ("authority_rebind", 25), ("state_rebind", 25)):
            self.exercise(case, code)

    def test_02_original_syscall_retry_and_drop_rules(self):
        for case, code, error in (("root_eintr", 0, 0), ("owner_open_eintr", 11, 4),
                ("lock_eintr", 13, 4), ("owner_read_eintr", 0, 0), ("owner_partial", 0, 0),
                ("owner_partial_eio", 9, 5), ("owner_close_eio", 0, 0)):
            self.exercise(case, code, error)

    def test_03_registry_races_and_unchanged_thirty_second_bound(self):
        for case, code, error in (("job_replace", 42, 0), ("job_touch", 42, 0),
                ("jobs_changed", 47, 0), ("predecessor_rebind", 25, 0),
                ("scan_deadline", 35, 0), ("job_read_eintr", 0, 0), ("job_partial_eio", 9, 5)):
            self.exercise(case, code, error, query=True)


if __name__ == "__main__":
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(KernelTests))
    exact = result.testsRun == 3 and not any((result.failures, result.errors, result.skipped,
        result.expectedFailures, result.unexpectedSuccesses)) and base.COUNTS == {
        "processes": 19, "closed_processes": 19, "requests": 37, "responses": 37}
    exact = exact and len(REPORTS) == 19 and {item["case"] for item in REPORTS} == set(CASES)
    if BACKEND == "native":
        exact = exact and framing.TRANSPORT_COUNTS == {
            "processes": 19, "closed_processes": 0, "requests": 63, "responses": 63}
    raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in base.ROWS)
    (EVIDENCE / "cases.jsonl").write_bytes(raw)
    transport = None
    if BACKEND == "native":
        framed = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in framing.TRANSPORT_ROWS)
        packed = gzip.compress(framed, mtime=0)
        (EVIDENCE / "async-transport.jsonl.gz").write_bytes(packed)
        transport = {"rows": len(framing.TRANSPORT_ROWS), "raw_bytes": len(framed),
            "raw_sha256": hashlib.sha256(framed).hexdigest(), "gzip_bytes": len(packed),
            "gzip_sha256": hashlib.sha256(packed).hexdigest()}
    artifact, identity, backend = executable()
    report = {"schema": "hepta.effect-fence.paired-kernel-qualification.v1",
        "status": "PASS" if result.wasSuccessful() and exact else "FAIL", "backend": backend,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses), "counts": base.COUNTS,
        "transport_counts": framing.TRANSPORT_COUNTS if BACKEND == "native" else None,
        "transport_corpus": transport,
        "elapsed_seconds": time.monotonic() - started, "kernel_reports": REPORTS,
        "cases_bytes": len(raw), "cases_sha256": hashlib.sha256(raw).hexdigest(),
        "executable_sha256": identity, "processes_closed": base.COUNTS["closed_processes"],
        "sources": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (Path(__file__).name, "fence_kernel_supervisor.py", "fence_worker_supervisor.py",
                "effect_fence_test_support.py", "fence_async_support.py", "effect_fence_async_serial_adapter.py")},
        "synthetic_syscall_errors_declared": True, "actual_owned_filesystem_races": True,
        "scan_deadline_seconds": 30, "deadline_or_clock_modified": False,
        "complete_effect_fence_owner": False, "whole_runtime_replaced": False}
    (EVIDENCE / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not (result.wasSuccessful() and exact))
