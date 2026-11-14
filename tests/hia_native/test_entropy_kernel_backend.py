"""Run identical Linux entropy cases on HIA or the complete original Rust owner."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from entropy_test_support import completion_counts
ROOT = Path(os.environ.get("HIA_REFERENCE_RUNTIME", HERE.parents[1])).resolve(strict=True)
SOURCE_PATHS = {name: HERE / name for name in (
    "test_entropy_kernel_backend.py", "entropy_backend_supervisor.py", "entropy_test_support.py")}
SOURCE_PATHS["io_fault_supervisor.py"] = ROOT / "tests/hia_native/io_fault_supervisor.py"
SOURCE_SHA256 = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for name, path in SOURCE_PATHS.items()}
ENTROPY = 0xfffffffd
COUNTS = {"processes": 0, "request_frames": 0, "original_owner_calls": 0,
          "kernel_completions": 0, "injected_completions": 0,
          "successful_outputs": 0, "entropy_refusals": 0}
TRACES = []


def frame(size):
    return b"HRENT001" + struct.pack("<QQ", size, 0)


class EntropyKernelBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference = os.environ.get("HIA_ENTROPY_REFERENCE_BINARY")
        cls.original = reference is not None
        if cls.original:
            cls.binary = Path(reference).resolve(strict=True)
            expected = os.environ["HIA_ENTROPY_REFERENCE_SHA256"]
            cls.provenance = {"owner": "original Rust SystemEntropy", "binary_sha256": expected}
        else:
            manifest = Path(os.environ["HIA_ENTROPY_MANIFEST"])
            metadata = json.loads(manifest.read_text())
            cls.binary = (manifest.parent / metadata["executable"]).resolve(strict=True)
            expected = metadata["executable_sha256"]
            cls.provenance = {"owner": "native HIA entropy policy and ELF packer",
                              "binary_sha256": expected,
                              "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                              "policy_source_sha256": metadata["policy_source_sha256"],
                              "packer_source_sha256": metadata["packer_source_sha256"]}
        assert hashlib.sha256(cls.binary.read_bytes()).hexdigest() == expected
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-owned-entropy-backends-")
        cls.directory = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_case(self, mode, sizes, expected=None):
        expected = list(sizes if expected is None else expected)
        self.assertEqual(len(expected), len(sizes))
        case_id = len(TRACES)
        log = self.directory / (str(case_id) + ".json")
        count_path = self.directory / (str(case_id) + ".owner-counts.json")
        command = [sys.executable, "-B", str(HERE / "entropy_backend_supervisor.py"),
                   "--log", str(log), "--mode", mode, "--", str(self.binary)]
        request = b"".join(map(frame, sizes))
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env=dict(os.environ, HIA_ENTROPY_ORACLE_COUNTS=str(count_path)))
        try:
            stdout, stderr = process.communicate(request, timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            self.fail("owned entropy process group exceeded the 15 second test deadline")
        self.assertEqual((process.returncode, stderr), (0, b""))
        trace = json.loads(log.read_text())
        self.assertIs(trace["owned_child_reaped"], True)
        self.assertEqual(trace["executable_sha256"], self.provenance["binary_sha256"])
        cursor, outputs, codes = 0, [], []
        for code in expected:
            self.assertLessEqual(cursor + 4, len(stdout))
            actual, = struct.unpack_from("<I", stdout, cursor)
            cursor += 4
            self.assertEqual(actual, code)
            payload = stdout[cursor:cursor + actual] if actual <= 128 else b""
            self.assertEqual(len(payload), actual if actual <= 128 else 0)
            cursor += len(payload)
            outputs.append(payload)
            codes.append(actual)
        self.assertEqual(cursor, len(stdout), "a refused fill must publish no payload")
        events = trace["events"]
        counts = Counter(x["kind"] for x in events)
        self.assertEqual(counts["probe"], int(any(sizes)))
        read_fds = {x["device_fd"] for x in events if x["kind"] == "read_urandom"}
        self.assertLessEqual(len(read_fds), 1, "one process retains one urandom cache")
        self.assertEqual(counts["close_urandom"], int(bool(read_fds) and not self.original))
        if self.original:
            self.assertEqual(json.loads(count_path.read_text()), {"original_owner_calls": len(sizes)})
            COUNTS["original_owner_calls"] += len(sizes)
        else:
            self.assertFalse(count_path.exists())
        COUNTS["processes"] += 1
        COUNTS["request_frames"] += len(sizes)
        COUNTS["kernel_completions"] += sum(x["completion"] == "kernel" for x in events)
        COUNTS["injected_completions"] += sum(x["completion"] != "kernel" for x in events)
        COUNTS["successful_outputs"] += sum(x <= 128 for x in codes)
        COUNTS["entropy_refusals"] += codes.count(ENTROPY)
        TRACES.append({"mode": mode, "sizes": sizes, "codes": codes,
                       "request_sha256": hashlib.sha256(request).hexdigest(),
                       "output_lengths": list(map(len, outputs)), "events": events,
                       "owned_child_reaped": True})
        return outputs, events, counts

    def test_real_entropy_sizes_and_empty_request(self):
        for size in (0, 1, 12, 32, 128):
            _, events, counts = self.run_case("observe", [size])
            self.assertEqual(counts, Counter({"probe": 1, "getrandom": 1}) if size else Counter())
            if size:
                self.assertEqual(events[-1], {"kind": "getrandom", "call": 1, "requested": size,
                                             "destination_delta": 0, "completion": "kernel"})

    def test_backend_probe_and_file_descriptor_are_cached(self):
        sizes = [32, 32, 32, 32, 12, 0, 32]
        for mode in ("observe", "probe_enosys", "probe_eperm"):
            _, events, counts = self.run_case(mode, sizes)
            if mode == "observe":
                self.assertEqual(counts, Counter({"probe": 1, "getrandom": 6}))
            else:
                wanted = Counter({"probe": 1, "open_random": 1, "poll": 1,
                                  "close_random": 1, "open_urandom": 1, "read_urandom": 6})
                if not self.original:
                    wanted["close_urandom"] = 1
                self.assertEqual(counts, wanted)
                self.assertEqual(events[0]["error"], 38 if mode == "probe_enosys" else 1)
            data = [x for x in events if x["kind"] in ("getrandom", "read_urandom")]
            self.assertEqual([x["requested"] for x in data], [x for x in sizes if x])
            self.assertTrue(all(x["destination_delta"] == 0 for x in data))

    def test_other_probe_errors_select_the_direct_backend(self):
        for mode, error in (("probe_eintr", 4), ("probe_eio", 5), ("probe_eagain", 11)):
            _, events, counts = self.run_case(mode, [32, 12])
            self.assertEqual(counts, Counter({"probe": 1, "getrandom": 2}))
            self.assertEqual(events[0]["error"], error)

    def test_direct_data_errors_do_not_change_the_cached_backend(self):
        for mode in ("eio", "enosys", "eagain", "zero"):
            outputs, events, counts = self.run_case(mode, [32], [ENTROPY])
            self.assertEqual(outputs, [b""])
            self.assertEqual(counts, Counter({"probe": 1, "getrandom": 1}))
            self.assertNotEqual(events[-1]["completion"], "kernel")

    def test_direct_and_fallback_interruptions_retry(self):
        for mode in ("eintr", "fallback_eintr"):
            _, events, counts = self.run_case(mode, [32, 12])
            data = [x for x in events if x["kind"] in ("getrandom", "read_urandom")]
            self.assertEqual([(x["requested"], x["destination_delta"]) for x in data],
                             [(32, 0), (32, 0), (12, 0)])
            self.assertEqual(data[0]["error"], 4)
            if mode == "fallback_eintr":
                self.assertEqual((counts["open_random"], counts["poll"], counts["open_urandom"]), (2, 3, 2))
                self.assertEqual([x["error"] for x in events if x["kind"] == "poll" and "error" in x], [4, 11])

    def test_fallback_failure_recovers_with_the_original_cache_rules(self):
        modes = {"fallback_open_error": (2, 1, 1, 1),
                 "fallback_poll_error": (2, 2, 2, 1),
                 "fallback_urandom_open_error": (2, 2, 2, 2),
                 "fallback_read_error": (1, 1, 1, 1)}
        for mode, expected in modes.items():
            outputs, _, counts = self.run_case(mode, [32, 12], [ENTROPY, 12])
            self.assertEqual(outputs[0], b"")
            self.assertEqual(tuple(counts[k] for k in ("open_random", "poll", "close_random", "open_urandom")), expected)
            self.assertEqual(counts["read_urandom"], 2 if mode == "fallback_read_error" else 1)

    def test_partial_bytes_advance_exactly_and_restart_at_the_buffer_origin(self):
        for mode in ("partial", "fallback_partial"):
            outputs, events, _ = self.run_case(mode, [32, 12])
            self.assertEqual(outputs, [bytes((i * 17) & 255 for i in range(1, 33)),
                                       bytes((i * 17) & 255 for i in range(33, 45))])
            data = [x for x in events if x["kind"] in ("getrandom", "read_urandom")]
            self.assertEqual([(x["requested"], x["destination_delta"], x["returned"]) for x in data],
                             [(32 - i, i, 1) for i in range(32)] + [(12 - i, i, 1) for i in range(12)])
            self.assertTrue(all(x["completion"] == "synthetic_partial_bytes" for x in data))

    def test_error_after_partial_bytes_discards_output_and_allows_the_next_request(self):
        for mode in ("partial_error", "fallback_partial_error"):
            outputs, events, _ = self.run_case(mode, [32, 12], [ENTROPY, 12])
            self.assertEqual(outputs[0], b"")
            data = [x for x in events if x["kind"] in ("getrandom", "read_urandom")]
            self.assertEqual([(x["requested"], x["destination_delta"]) for x in data], [(32, 0), (27, 5), (12, 0)])
            self.assertEqual(data[0]["returned"], 5)
            self.assertEqual(data[1]["error"], 5)
            self.assertEqual(data[2]["completion"], "kernel")


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2)
    source_unchanged = SOURCE_SHA256 == {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                       for name, path in SOURCE_PATHS.items()}
    report = {"schema": "hepta.runtime.entropy-kernel-backend-test.v1",
              **completion_counts(result.result, 8),
              "scope": "Linux direct and fallback entropy under owned-child syscall controls",
              "provenance": getattr(EntropyKernelBackend, "provenance", {}),
              "counts": COUNTS, "traces": TRACES,
              "source_sha256": SOURCE_SHA256, "source_unchanged": source_unchanged,
              "cleanup_difference": "Native closes its cached urandom descriptor at EOF; original cache is released by process exit."}
    if not source_unchanged:
        report["status"] = "FAIL"
    target = os.environ.get("HIA_ENTROPY_KERNEL_REPORT")
    if target:
        path = Path(target)
        assert not path.exists(), "kernel evidence must not overwrite a previous run"
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "traces"}, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
