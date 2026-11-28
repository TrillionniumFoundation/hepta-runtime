"""Native entropy framing and transport controls outside the original RNG ABI."""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from entropy_test_support import completion_counts
COUNTS = {"native_processes": 0, "partial_frame_refusals": 0,
          "invalid_frame_refusals": 0, "cli_refusals": 0,
          "closed_output_controls": 0, "invalid_kernel_success_controls": 0}


def frame(size, reserved=0):
    return b"HRENT001" + struct.pack("<QQ", size, reserved)


class EntropyTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ["HIA_ENTROPY_MANIFEST"])
        metadata = json.loads(path.read_text())
        cls.binary = (path.parent / metadata["executable"]).resolve(strict=True)
        cls.digest = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        assert cls.digest == metadata["executable_sha256"]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-entropy-transport-")
        cls.directory = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def observed(self, request, expected_exit, expected_output, mode="observe"):
        log = self.directory / (str(COUNTS["native_processes"]) + ".json")
        run = subprocess.run([sys.executable, "-B", str(HERE / "entropy_backend_supervisor.py"),
                              "--mode", mode, "--log", str(log), "--", str(self.binary)],
                             input=request, capture_output=True, timeout=10)
        COUNTS["native_processes"] += 1
        self.assertEqual((run.returncode, run.stdout, run.stderr),
                         (expected_exit, expected_output, b""))
        result = json.loads(log.read_text())
        self.assertIs(result["owned_child_reaped"], True)
        self.assertEqual(result["executable_sha256"], self.digest)
        return result["events"]

    def test_empty_stream_and_empty_fill(self):
        self.assertEqual(self.observed(b"", 0, b""), [])
        self.assertEqual(self.observed(frame(0), 0, bytes(4)), [])

    def test_truncated_frame_is_fatal_without_a_partial_response(self):
        for size in (1, 8, 16, 23):
            self.assertEqual(self.observed(frame(32)[:size], 2, b""), [])
            COUNTS["partial_frame_refusals"] += 1
        self.assertEqual(self.observed(frame(0) + b"H", 2, bytes(4)), [])
        COUNTS["partial_frame_refusals"] += 1

    def test_invalid_frames_are_refused_and_the_same_process_continues(self):
        invalid = [b"x" * 24, frame(129), frame((1 << 64) - 1), frame(0, 1)]
        expected = struct.pack("<5I", *([0xffffffff] * 4), 0)
        self.assertEqual(self.observed(b"".join(invalid) + frame(0), 0, expected), [])
        COUNTS["invalid_frame_refusals"] += len(invalid)

    def test_command_line_cannot_select_paths_or_change_the_profile(self):
        for args in (["--help"], ["32"], ["--local-read-profile", "/"]):
            run = subprocess.run([str(self.binary), *args], input=b"", capture_output=True,
                                 timeout=5, env={"PATH": ""})
            self.assertEqual((run.returncode, run.stdout, run.stderr), (64, b"", b""))
            COUNTS["native_processes"] += 1
            COUNTS["cli_refusals"] += 1

    def test_closed_output_uses_the_declared_transport_failure(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE,
                                       stdout=write_fd, stderr=subprocess.PIPE,
                                       env={"PATH": ""}, restore_signals=True)
        finally:
            os.close(write_fd)
        _, stderr = process.communicate(frame(0), timeout=5)
        self.assertEqual((process.returncode, stderr), (74, b""))
        COUNTS["native_processes"] += 1
        COUNTS["closed_output_controls"] += 1

    def test_impossible_kernel_byte_count_is_not_published(self):
        events = self.observed(frame(32) + frame(0), 0,
                               struct.pack("<II", 0xfffffffd, 0), "oversized")
        self.assertEqual([event["kind"] for event in events], ["probe", "getrandom"])
        self.assertEqual(events[-1]["requested"], 32)
        self.assertEqual(events[-1]["returned"], 33)
        COUNTS["invalid_kernel_success_controls"] += 1


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2)
    report = {"schema": "hepta.runtime.entropy-transport-test.v1",
              **completion_counts(result.result, 6),
              "scope": "native fixed transport; not original SystemEntropy behavior",
              "counts": COUNTS}
    target = os.environ.get("HIA_ENTROPY_TRANSPORT_REPORT")
    if target:
        path = Path(target)
        assert not path.exists(), "entropy evidence must not overwrite a previous run"
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
