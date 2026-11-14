"""Retired capabilities never alias a reused slot or grow historical storage."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fence_async_support import Fixture, COUNTS, ROWS

EVIDENCE = Path(os.environ["HIA_FENCE_LIFETIME_CORPUS_DIR"])
EVIDENCE.mkdir(parents=True, exist_ok=True)
MEMORY = []


def mapped(pid):
    total = 0
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        first, last = line.split()[0].split("-")
        total += int(last, 16) - int(first, 16)
    return total


class LifetimeTests(unittest.TestCase):
    def test_01_history_does_not_retain_dead_records(self):
        with Fixture() as fixture:
            session = fixture.session("recycled-history")
            old = session.create()
            session.cancel(old)
            before = mapped(session.process.pid)
            for index in range(16384):
                future = session.create()
                self.assertEqual(future, index + 2)
                session.cancel(future)
            after = mapped(session.process.pid)
            self.assertEqual(after, before)
            self.assertEqual(session.call(2, old), (2, old, 0, 0, 0, 0, 0))
            fresh = session.create()
            self.assertEqual(fresh, 16386)
            session.cancel(fresh)
            self.assertEqual(session.stats(), (16386, 0, 0, 0, 16386, 0, 0, 0, 0))
            MEMORY.append({"case": session.case, "before": before, "after": after,
                           "historical_futures": 16386, "max_live_records": 1})
            session.close()

    def test_02_live_capacity_grows_and_retired_ids_stay_invalid(self):
        with Fixture() as fixture:
            session = fixture.session("live-record-growth")
            self.assertEqual(session.stats(), (0,) * 9)
            before = mapped(session.process.pid)
            futures = [session.create() for _ in range(8193)]
            self.assertEqual(futures, list(range(1, 8194)))
            for future in futures:
                session.cancel(future)
            after = mapped(session.process.pid)
            self.assertEqual(after - before, 1048576)
            for stale in (futures[0], futures[-1]):
                self.assertEqual(session.call(2, stale), (2, stale, 0, 0, 0, 0, 0))
            fresh = session.create()
            self.assertEqual(fresh, 8194)
            session.cancel(fresh)
            self.assertEqual(session.stats(), (8194, 0, 0, 0, 8194, 0, 0, 0, 0))
            MEMORY.append({"case": session.case, "before": before, "after": after,
                           "historical_futures": 8194, "max_live_records": 8193})
            session.close()


if __name__ == "__main__":
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LifetimeTests))
    exact = result.testsRun == 2 and not any((result.failures, result.errors, result.skipped,
        result.expectedFailures, result.unexpectedSuccesses)) and COUNTS == {
        "processes": 2, "closed_processes": 2, "requests": 49166, "responses": 49166}
    raw = b"".join(json.dumps(row, sort_keys=True).encode() + b"\n" for row in ROWS)
    zipped = gzip.compress(raw, mtime=0)
    (EVIDENCE / "cases.jsonl.gz").write_bytes(zipped)
    manifest = Path(os.environ["HIA_FENCE_ASYNC_MANIFEST"])
    report = {"schema": "hepta.effect-fence.lifetime-qualification.v1",
              "status": "PASS" if result.wasSuccessful() and exact else "FAIL",
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses), "counts": COUNTS,
              "elapsed_seconds": time.monotonic() - started, "observed_mapping_bytes": MEMORY,
              "cases_sha256": hashlib.sha256(raw).hexdigest(), "cases_bytes": len(raw),
              "gzip_sha256": hashlib.sha256(zipped).hexdigest(), "gzip_bytes": len(zipped),
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
              "elf_sha256": json.loads(manifest.read_bytes())["elf_sha256"],
              "complete_effect_fence_owner": False, "whole_runtime_replaced": False}
    (EVIDENCE / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not (result.wasSuccessful() and exact))
