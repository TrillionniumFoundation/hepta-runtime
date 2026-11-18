"""Actual Linux thread, queue, descriptor and cache controls for the candidate."""
from pathlib import Path
import fcntl
import hashlib
import json
import os
import re
import struct
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fence_async_support import Fixture, COUNTS, ROWS

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = Path(os.environ["HIA_FENCE_ASYNC_CORPUS_DIR"])
EVIDENCE.mkdir(parents=True, exist_ok=True)
TRACES = []


def until(predicate, timeout=5):
    end = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= end:
            raise AssertionError("owned kernel state did not reach its expected boundary")
        time.sleep(0.005)


def target_pid(session):
    if session.trace is None:
        return session.process.pid
    name = Path(f"/proc/{session.process.pid}/task/{session.process.pid}/children")
    found = []
    until(lambda: bool(found.extend(name.read_text().split()) or found))
    if len(found) != 1:
        raise AssertionError(("unexpected owned trace children", found))
    return int(found[0])


def task_count(pid):
    return len(list(Path(f"/proc/{pid}/task").iterdir()))


def exclusive(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    fcntl.flock(fd, fcntl.LOCK_UN)
    return True


def retain_trace(session):
    raw = session.trace.read_bytes()
    path = EVIDENCE / (session.case + ".trace")
    path.write_bytes(raw)
    TRACES.append({"path": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    return raw.decode()


def shared_lock_completions(trace):
    """Bind split strace entry/exit records to the same observed worker TID."""
    pending, completed = {}, []
    for line in trace.splitlines():
        entry = re.fullmatch(r"(\d+)\s+flock\((\d+), LOCK_SH(.*)", line)
        if entry:
            tid, fd, tail = int(entry[1]), int(entry[2]), entry[3]
            if tid in pending:
                raise AssertionError("duplicate unfinished shared-lock entry")
            if tail == " <unfinished ...>":
                pending[tid] = fd
            elif re.fullmatch(r"\)\s+= 0", tail):
                completed.append((tid, fd))
            else:
                raise AssertionError(("unexpected shared-lock result", line))
            continue
        resumed = re.fullmatch(r"(\d+)\s+<\.\.\. flock resumed>\)\s+= 0", line)
        if resumed:
            tid = int(resumed[1])
            if tid not in pending:
                raise AssertionError("unpaired shared-lock completion")
            completed.append((tid, pending.pop(tid)))
    if pending:
        raise AssertionError(("shared-lock call never completed", pending))
    return completed


class AsyncOwnerTests(unittest.TestCase):
    def test_01_unpolled_and_configuration_preflight(self):
        with Fixture() as f:
            p = f.session("unpolled", trace=True)
            future = p.create()
            p.cancel(future)
            self.assertEqual(p.stats(), (1, 0, 0, 0, 1, 0, 0, 0, 0))
            p.close()
            trace = retain_trace(p)
            self.assertNotIn("clone(", trace)
            self.assertNotIn('".owner.lock"', trace)
        for label, config, code in (
            ("legacy", {"HEPTA_EFFECT_OWNER_FENCE_DIR": None, "HEPTA_EFFECT_OWNER_SELF": None}, 0),
            ("partial", {"HEPTA_EFFECT_OWNER_SELF": None}, 2),
            ("required", {"HEPTA_EFFECT_OWNER_FENCE_REQUIRED": "0"}, 1),
        ):
            with Fixture() as f:
                p = f.session(label, config=config, trace=True)
                result = p.await_future(p.create())
                self.assertEqual(result[3:], (code, 0, 0, 0))
                if code == 0:
                    query = p.create(permit=result[2], method=2, host="", key=None)
                    self.assertEqual(p.await_future(query)[3:], (0, 0, 0, 0))
                    p.release(result[2])
                self.assertEqual(p.stats()[2], 0)
                p.close()
                trace = retain_trace(p)
                self.assertNotIn("clone(", trace)
                self.assertNotIn('".owner.lock"', trace)

    def test_02_twelve_blocked_workers_and_cancelled_ownership(self):
        with Fixture() as f, open(f.authority / ".owner.lock", "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            p = f.session("twelve-workers")
            futures = [p.create() for _ in range(12)]
            for future in futures:
                p.submit(future)
            until(lambda: task_count(p.process.pid) == 13)
            self.assertEqual(p.stats()[6:8], (12, 0))
            for future in futures[:4]:
                p.cancel(future)
            fcntl.flock(lock, fcntl.LOCK_UN)
            permits = [p.await_future(future)[2] for future in futures[4:]]
            until(lambda: task_count(p.process.pid) == 1)
            self.assertEqual(p.stats(), (12, 12, 12, 12, 4, 4, 0, 0, 8))
            self.assertFalse(exclusive(lock.fileno()))
            for permit in permits:
                p.release(permit)
            self.assertTrue(exclusive(lock.fileno()))
            self.assertEqual(p.stats()[5:], (12, 0, 0, 0))
            p.close()

    def test_03_cancelled_queued_workers_still_validate(self):
        with Fixture() as f, open(f.authority / ".owner.lock", "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            p = f.session("queued-cancel", single=True, trace=True)
            pid = target_pid(p)
            futures = [p.create() for _ in range(4)]
            for future in futures:
                p.submit(future)
            self.assertEqual(p.stats()[6:8], (1, 3))
            for future in futures:
                p.cancel(future)
            f.record(phase="frozen")
            fcntl.flock(lock, fcntl.LOCK_UN)
            until(lambda: p.trace.read_text().count('".owner.json"') == 8 and task_count(pid) == 1)
            self.assertEqual(p.stats(), (4, 4, 4, 4, 4, 0, 0, 0, 0))
            self.assertTrue(exclusive(lock.fileno()))
            p.close()
            trace = retain_trace(p)
            self.assertEqual(trace.count('".owner.json"'), 8)
            locks = shared_lock_completions(trace)
            self.assertEqual(len(locks), 4)
            self.assertEqual(len({tid for tid, _ in locks}), 4)
            with self.assertRaises(AssertionError):
                shared_lock_completions("1 flock(7, LOCK_SH <unfinished ...>\n")
            with self.assertRaises(AssertionError):
                shared_lock_completions("1 <... flock resumed>) = 0\n")

    def test_04_cancel_cleanup_during_partial_input(self):
        with Fixture() as f, open(f.authority / ".owner.lock", "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            p = f.session("partial-input-cancel")
            future = p.create()
            p.submit(future)
            p.cancel(future)
            wire = b"HFFASY01" + struct.pack("<7Q", 7, 0, 0, 0, 0, 0, 0)
            header = struct.pack("<Q", len(wire))
            p.process.stdin.write(header[:4]); p.process.stdin.flush()
            fcntl.flock(lock, fcntl.LOCK_UN)
            until(lambda: task_count(p.process.pid) == 1 and exclusive(lock.fileno()))
            p.pending = wire
            COUNTS["requests"] += 1
            p.process.stdin.write(header[4:] + wire); p.process.stdin.flush()
            self.assertEqual(p.receive(), (1, 1, 1, 1, 1, 1, 0, 0, 0))
            p.close()

    def test_05_global_replay_cache_across_two_permits(self):
        with Fixture("v11") as f:
            job = f.job()
            p = f.session("global-cache")
            first, second = p.acquire(), p.acquire()
            old = p.create(permit=first, method=2, host="local", key="old")
            fresh = p.create(permit=second, method=2, host="local", key="fresh")
            p.submit(old); p.submit(fresh)
            self.assertEqual(p.await_future(old)[3], 34)
            self.assertEqual(p.await_future(fresh)[3], 0)
            job.write_bytes(b"invalid in-place replacement; directory stamp unchanged")
            again = p.create(permit=second, method=2, host="local", key="old")
            self.assertEqual(p.await_future(again)[3], 34)
            p.release(first); p.release(second)
            self.assertEqual(p.stats()[6:], (0, 0, 0))
            p.close()

    def test_06_unpolled_query_borrow_delays_permit_drop(self):
        with Fixture("v11") as f, open(f.authority / ".owner.lock", "rb") as lock:
            f.job()
            p = f.session("query-borrow", close_stderr=True)
            permit = p.acquire()
            query = p.create(permit=permit, method=2, host="local", key="fresh")
            p.release(permit)
            self.assertFalse(exclusive(lock.fileno()))
            self.assertEqual(p.call(4, permit, 2, host="local", key="other")[0], 2)
            p.cancel(query)
            self.assertTrue(exclusive(lock.fileno()))
            self.assertEqual(p.stats(), (2, 1, 1, 1, 1, 1, 0, 0, 0))
            p.close()

    def test_07_eof_waits_for_submitted_queue(self):
        with Fixture() as f, open(f.authority / ".owner.lock", "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            p = f.session("eof-queue", single=True, trace=True)
            futures = [p.create() for _ in range(4)]
            for future in futures:
                p.submit(future)
            self.assertEqual(p.stats()[6:8], (1, 3))
            p.process.stdin.close()
            self.assertIsNone(p.process.poll())
            fcntl.flock(lock, fcntl.LOCK_UN)
            p.close()
            trace = retain_trace(p)
            self.assertEqual(trace.count('".owner.json"'), 8)
            self.assertEqual(len(shared_lock_completions(trace)), 4)
            self.assertTrue(exclusive(lock.fileno()))


if __name__ == "__main__":
    start = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AsyncOwnerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exact = result.testsRun == 7 and not any((result.failures, result.errors, result.skipped,
        result.expectedFailures, result.unexpectedSuccesses)) and COUNTS == {
        "processes": 10, "closed_processes": 10, "requests": 111, "responses": 111}
    report = {"schema": "hepta.runtime.effect-fence-async.prototype-tests.v1",
              "status": "PASS" if result.wasSuccessful() and exact else "FAIL",
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses), "counts": COUNTS,
              "elapsed_seconds": time.monotonic()-start, "traces": TRACES,
              "complete_effect_fence_owner": False, "whole_runtime_replaced": False}
    raw = b"".join(json.dumps(row, sort_keys=True).encode()+b"\n" for row in ROWS)
    (EVIDENCE / "cases.jsonl").write_bytes(raw)
    report["cases_sha256"] = hashlib.sha256(raw).hexdigest()
    report["sources"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        Path(__file__), Path(__file__).with_name("fence_async_support.py"),
        Path(__file__).with_name("effect_fence_test_support.py"))}
    report["profiles"] = {label: json.loads(Path(os.environ[name]).read_bytes())["elf_sha256"]
        for label, name in (("default", "HIA_FENCE_ASYNC_MANIFEST"), ("single_worker_fixture", "HIA_FENCE_ASYNC_SINGLE_MANIFEST"))}
    (EVIDENCE / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2)+"\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not (result.wasSuccessful() and exact))
