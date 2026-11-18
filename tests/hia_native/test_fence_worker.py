"""Actual fixed-entry worker traps, cache poison and kernel retirement controls."""
from pathlib import Path
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fence_async_support import Fixture, Session, COUNTS, ROWS

EVIDENCE = Path(os.environ["HIA_FENCE_WORKER_CORPUS_DIR"])
EVIDENCE.mkdir(parents=True, exist_ok=True)
REPORTS = []


class FaultSession(Session):
    def __init__(self, fixture, mode, inherited_mask):
        self.case = mode + ("-blocked-sigill" if inherited_mask else "-ordinary-mask")
        manifest = Path(os.environ["HIA_FENCE_ASYNC_MANIFEST"]).resolve(strict=True)
        metadata = json.loads(manifest.read_bytes())
        self.executable = manifest.parent / metadata["executable"]
        self.metadata, self.pending, self.trace = metadata, None, None
        if hashlib.sha256(self.executable.read_bytes()).hexdigest() != metadata["elf_sha256"]:
            raise AssertionError("actual worker ELF differs")
        self.report_path = EVIDENCE / (self.case + ".json")
        args = ["/usr/bin/python3", "-I", "-B", str(Path(__file__).with_name("fence_worker_supervisor.py")),
                "--manifest", str(manifest), "--report", str(self.report_path), "--mode", mode,
                "--state-root", str(fixture.state)]
        if inherited_mask:
            args.append("--block-sigill")
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={"PATH": "", "HEPTA_EFFECT_OWNER_FENCE_DIR": str(fixture.authority),
                "HEPTA_EFFECT_OWNER_SELF": fixture.role})
        COUNTS["processes"] += 1
        fixture.sessions.append(self)

    def closed_report(self):
        self.close()
        raw = self.report_path.read_bytes()
        report = json.loads(raw)
        if report["status"] != "PASS" or not report["all_owned_tasks_reaped"]:
            raise AssertionError(("actual worker report refused", report))
        if report["executable_sha256"] != self.metadata["elf_sha256"]:
            raise AssertionError("actual worker evidence uses a different ELF")
        REPORTS.append({"path": self.report_path.name, "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})
        return report


def exclusive(file):
    try:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    fcntl.flock(file, fcntl.LOCK_UN)
    return True


class WorkerFaultTests(unittest.TestCase):
    def admission(self, inherited_mask):
        with Fixture() as fixture, open(fixture.authority / ".owner.lock", "rb") as lock:
            session = FaultSession(fixture, "admission", inherited_mask)
            failed = session.await_future(session.create())
            self.assertEqual(failed[2:], (0, 54, 0, 0, 0))
            self.assertTrue(exclusive(lock))
            permit = session.acquire()
            self.assertFalse(exclusive(lock))
            session.release(permit)
            self.assertTrue(exclusive(lock))
            self.assertEqual(session.stats(), (2, 2, 2, 2, 0, 1, 0, 0, 0))
            report = session.closed_report()
            self.assertEqual(len(report["exit_statuses"]), 3)
            self.assertEqual(sum(e["kind"] == "actual_kernel_sigill" for e in report["events"]), 1)

    def cache(self, inherited_mask):
        with Fixture("v11") as fixture, open(fixture.authority / ".owner.lock", "rb") as lock:
            fixture.job()
            session = FaultSession(fixture, "cache", inherited_mask)
            first = session.acquire()
            failed = session.await_future(session.create(permit=first, method=2, host="local", key="fresh"))
            self.assertEqual(failed[2:], (0, 54, 0, 0, 0))
            self.assertFalse(exclusive(lock))
            poisoned = session.await_future(session.create(permit=first, method=2, host="local", key="other"))
            self.assertEqual(poisoned[3:], (32, 0, 7, 1))
            second = session.acquire()
            again = session.await_future(session.create(permit=second, method=2, host="local", key="old"))
            self.assertEqual(again[3:], (32, 0, 7, 1))
            session.release(first)
            self.assertFalse(exclusive(lock))
            session.release(second)
            self.assertTrue(exclusive(lock))
            self.assertEqual(session.stats(), (5, 5, 5, 5, 0, 2, 0, 0, 0))
            report = session.closed_report()
            self.assertEqual(len(report["exit_statuses"]), 6)
            armed = [e for e in report["events"] if e["kind"] == "armed_fixed_owner_ud2"]
            self.assertEqual(len(armed), 1)
            self.assertEqual(armed[0]["cache_held"], 1)
            self.assertGreater(len(armed[0]["borrowed_fds"]), 0)

    def test_01_actual_admission_worker_trap(self):
        self.admission(False)

    def test_02_inherited_blocked_signal_admission(self):
        self.admission(True)

    def test_03_actual_query_worker_trap_and_global_poison(self):
        self.cache(False)

    def test_04_inherited_blocked_signal_cache(self):
        self.cache(True)


if __name__ == "__main__":
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WorkerFaultTests))
    exact = result.testsRun == 4 and not any((result.failures, result.errors, result.skipped,
        result.expectedFailures, result.unexpectedSuccesses)) and COUNTS == {
        "processes": 4, "closed_processes": 4, "requests": 38, "responses": 38}
    raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in ROWS)
    (EVIDENCE / "cases.jsonl").write_bytes(raw)
    report = {"schema": "hepta.effect-fence.worker-qualification.v1",
              "status": "PASS" if result.wasSuccessful() and exact else "FAIL",
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses), "counts": COUNTS,
              "elapsed_seconds": time.monotonic() - started, "kernel_reports": REPORTS,
              "cases_sha256": hashlib.sha256(raw).hexdigest(),
              "sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
                  Path(__file__), Path(__file__).with_name("fence_worker_supervisor.py"),
                  Path(__file__).with_name("fence_async_support.py"),
                  Path(__file__).with_name("effect_fence_test_support.py"))},
              "complete_effect_fence_owner": False, "whole_runtime_replaced": False}
    (EVIDENCE / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not (result.wasSuccessful() and exact))
