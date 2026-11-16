"""Actual fixed native syscalls and an unchanged-original-compatible test recipe."""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOKEN = b"X" * 32
CASES = []
COUNTS = {"processes": 0, "token_processes": 0, "owner_processes": 0,
          "kernel_supervised_processes": 0, "controlled_fault_processes": 0,
          "injected_errno_completions": 0, "injected_zero_completions": 0,
          "actual_fixture_mutations": 0, "original_owner_calls": 0, "native_owner_calls": 0}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class LoaderKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ["HIA_AUTHORITY_PROBE_MANIFEST"])
        metadata = json.loads(cls.manifest.read_bytes())
        assert metadata["compiler_commit"] == "d3e2c90173cf733e42b299d0c4274df4b593a12f"
        assert metadata["policy_source_sha256"] == sha((ROOT / "native/authority_loader.hepta").read_bytes())
        assert metadata["packer_source_sha256"] == sha((HERE / "authority_loader_probe_packer.hepta").read_bytes())
        cls.original = "HIA_AUTHORITY_REFERENCE_BINARY" in os.environ
        cls.exe = Path(os.environ["HIA_AUTHORITY_REFERENCE_BINARY"]) if cls.original else cls.manifest.parent / metadata["executable"]
        expected = os.environ["HIA_AUTHORITY_REFERENCE_SHA256"] if cls.original else metadata["executable_sha256"]
        assert sha(cls.exe.read_bytes()) == expected
        cls.executable_sha = expected
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-private-token-kernel-")
        cls.directory = Path(cls.temporary.name)
        cls.report_directory = None
        if "HIA_AUTHORITY_KERNEL_CORPUS_DIR" in os.environ:
            cls.report_directory = Path(os.environ["HIA_AUTHORITY_KERNEL_CORPUS_DIR"])
            cls.report_directory.mkdir(parents=True, exist_ok=False)

    @classmethod
    def tearDownClass(cls):
        assert sha(cls.exe.read_bytes()) == cls.executable_sha
        cls.temporary.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=self.directory)
        self.folder = Path(self.temp.name)
        self.file = self.folder / "token"

    def tearDown(self):
        self.temp.cleanup()

    def make(self, data=TOKEN + b"\n", mode=0o600, path=None):
        path = self.file if path is None else path
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def probe(self, label, expected, body=None, *, path=None, kind="token", supervisor=None,
              closed_stderr=False, fixture_spec=None):
        path = self.file if path is None else path
        COUNTS["processes"] += 1
        COUNTS[kind + "_processes"] += 1
        COUNTS["original_owner_calls" if self.original else "native_owner_calls"] += 1
        number = COUNTS["processes"]
        if kind == "owner":
            command = [str(self.exe), "--stdio-owner-probe" if self.original else "--stdio-owner"]
        else:
            command = [str(self.exe), "--token-probe" if self.original else "--token-file", str(path)]
        log = self.folder / ("trace-" + str(number) + ".json")
        if supervisor:
            COUNTS["kernel_supervised_processes"] += 1
            prefix = [sys.executable, "-I", "-B", str(HERE / "authority_loader_supervisor.py"),
                      "--kind", kind, "--mode", supervisor, "--log", str(log)]
            if kind == "token":
                prefix += ["--fixture", str(path)]
            command = prefix + ["--"] + command
        env = dict(os.environ, PATH="")
        run = subprocess.run(command, input=b"untrusted stdin cannot choose a token pathname\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=20,
            preexec_fn=(lambda: os.close(2)) if closed_stderr else None)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(run.stderr, b"")
        self.assertGreaterEqual(len(run.stdout), 4)
        code = struct.unpack_from("<I", run.stdout)[0]
        output = run.stdout[4:]
        self.assertEqual(code, expected, label)
        self.assertEqual(len(output), code if code <= 4096 else 0)
        if body is not None:
            self.assertEqual(output, body)
        trace = None
        if supervisor:
            trace = json.loads(log.read_bytes())
            self.assertTrue(trace["owned_process_reaped"] and trace["executable_unchanged"])
            self.assertEqual(trace["executable_sha256"], self.executable_sha)
            self.assertEqual(trace["exit_code"], 0)
            self.assertEqual(trace["fault_fired"], supervisor != "observe")
            COUNTS["controlled_fault_processes"] += supervisor != "observe"
            COUNTS["injected_errno_completions"] += sum(event["effect"] == "injected_errno" for event in trace["events"])
            COUNTS["injected_zero_completions"] += sum(event["effect"] == "injected_zero_read" for event in trace["events"])
            COUNTS["actual_fixture_mutations"] += supervisor in ("rewrite", "chmod", "hardlink", "replace_path", "replace_after_stat")
            if self.report_directory:
                (self.report_directory / f"trace-{number:03d}.json").write_bytes(log.read_bytes())
        CASES.append({"case": label, "ordinal": number, "kind": kind, "supervisor": supervisor,
            "closed_stderr": closed_stderr, "fixture": fixture_spec, "code": code,
            "output_hex": output.hex() if kind == "token" else None,
            "output_bytes": len(output), "stdout_sha256": sha(run.stdout),
            "normal_random_bytes_compared": False if kind == "owner" else None,
            "trace": trace})
        return trace

    def test_token_length_lf_and_all_printable_ascii_edges(self):
        for size in [0, 1, 30, 31, 32, 33, 63, 4095, 4096, 4097, 4098, 4099, 8192]:
            for suffix in [b"", b"\n", b"\r\n", b"\n\n"]:
                data = b"x" * size + suffix
                admitted = size >= 32 and size <= 4096 and suffix in (b"", b"\n")
                self.make(data)
                self.probe(f"length-{size}-suffix-{suffix.hex()}", size if admitted else 0xfffffffa,
                    b"x" * size if admitted else b"", fixture_spec={"kind": "regular", "bytes_hex": data.hex(), "mode": 0o600})
        for value in [0, 9, 10, 13, 31, 32, 33, 34, 65, 126, 127, 128, 255]:
            data = bytes([value]) * 32
            admitted = 33 <= value <= 126
            self.make(data)
            self.probe(f"scalar-{value}", 32 if admitted else 0xfffffffa, data if admitted else b"",
                fixture_spec={"kind": "regular", "bytes_hex": data.hex(), "mode": 0o600})
        data = bytes(range(33, 127)) * 4
        self.make(data)
        self.probe("all-printable-ascii", len(data), data,
            fixture_spec={"kind": "regular", "bytes_hex": data.hex(), "mode": 0o600})

    def test_descriptor_file_type_mode_links_and_argv_bytes(self):
        for mode in [0o600, 0o640, 0o604, 0o700, 0o400, 0o660, 0o4600, 0o2600, 0o1600]:
            self.make(mode=mode)
            self.probe(f"mode-{mode:o}", 32 if mode == 0o600 else 0xfffffffc,
                TOKEN if mode == 0o600 else b"", fixture_spec={"kind": "regular", "bytes_hex": (TOKEN + b"\n").hex(), "mode": mode})
        self.make()
        alias = self.folder / "alias"
        os.link(self.file, alias)
        self.probe("hardlink", 0xfffffffc, b"", fixture_spec={"kind": "hardlink", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})
        alias.unlink()
        alias.symlink_to(self.file)
        self.probe("final-symlink", 0xfffffffd, b"", path=alias,
            fixture_spec={"kind": "final_symlink", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})
        alias.unlink()
        alias.symlink_to(self.folder, target_is_directory=True)
        self.probe("parent-symlink", 32, TOKEN, path=alias / "token",
            fixture_spec={"kind": "parent_symlink", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})
        self.probe("directory", 0xfffffffc, b"", path=self.folder,
            fixture_spec={"kind": "directory"})
        fifo = self.folder / "fifo"
        os.mkfifo(fifo, 0o600)
        self.probe("nonblocking-fifo", 0xfffffffc, b"", path=fifo,
            fixture_spec={"kind": "fifo", "mode": 0o600})
        self.probe("empty-path", 0xfffffffd, b"", path="", fixture_spec={"kind": "empty_path"})
        self.probe("absent-file", 0xfffffffd, b"", path=self.folder / "absent", fixture_spec={"kind": "absent"})
        raw_path = self.folder / os.fsdecode(b"credential-\xff")
        self.make(path=raw_path)
        self.probe("non-utf8-argv-path", 32, TOKEN, path=raw_path,
            fixture_spec={"kind": "non_utf8_name", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})
        self.probe("closed-stderr-descriptor-two", 32, TOKEN, closed_stderr=True,
            fixture_spec={"kind": "regular", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})

    def test_real_descriptor_races_and_read_ceiling(self):
        for mode in ["rewrite", "chmod", "hardlink", "replace_path", "replace_after_stat"]:
            self.make()
            trace = self.probe(mode, 32 if mode == "replace_after_stat" else 0xfffffffb,
                TOKEN if mode == "replace_after_stat" else b"", supervisor=mode,
                fixture_spec={"kind": "regular", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})
            self.assertEqual(sum(event["action"] == "close" for event in trace["events"]), 1)
            for extra in [self.file.with_suffix(".retained"), self.file.with_suffix(".second-link")]:
                extra.unlink(missing_ok=True)
        self.make(b"x" * 8192)
        trace = self.probe("bounded-take-4098", 0xfffffffa, b"", supervisor="observe",
            fixture_spec={"kind": "regular", "bytes_hex": (b"x" * 8192).hex(), "mode": 0o600})
        closed = [event for event in trace["events"] if event["action"] == "close"]
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]["descriptor_offset_before"], 4098)

    def test_errno_retry_cleanup_and_drop_close_precedence(self):
        cases = [("observe", 32), ("open_eintr", 32), ("read_eintr", 32), ("read_error", 0xffffd005),
            ("read_error_after_prefix", 0xffffd005), ("read_and_close_error", 0xffffd005), ("stat_and_close_error", 0xffffd005),
            ("read_zero", 0xfffffffa), ("stat_before_eintr", 0xffffd004), ("stat_after_eintr", 0xffffd004),
            ("stat_after_error", 0xffffd005), ("close_eintr", 32), ("close_error", 32)]
        for mode, code in cases:
            self.make()
            trace = self.probe(mode, code, TOKEN if code == 32 else b"", supervisor=mode,
                fixture_spec={"kind": "regular", "bytes_hex": (TOKEN + b"\n").hex(), "mode": 0o600})
            self.assertEqual(sum(event["action"] == "close" for event in trace["events"]), 1)
            opens = [event for event in trace["events"] if event["action"] == "open_token"]
            self.assertEqual(len(opens), 2 if mode == "open_eintr" else 1)
            self.assertTrue(all(event["flags"] == 0xa0800 for event in opens))

    def test_owner_literal_device_exact_read_and_ignored_close(self):
        for mode in ["observe", "open_eintr", "read_eintr", "read_error", "read_zero", "close_eintr", "close_error"]:
            expected = 0xfffffff9 if mode in ("read_error", "read_zero") else 32
            trace = self.probe("owner-" + mode, expected, b"" if expected != 32 else None,
                kind="owner", supervisor=mode, fixture_spec={"kind": "fixed_urandom"})
            self.assertEqual(sum(event["action"] == "close" for event in trace["events"]), 1)
            reads = [event for event in trace["events"] if event["action"] == "read"]
            self.assertTrue(reads and all(0 < event["requested_bytes"] <= 32 for event in reads))


if __name__ == "__main__":
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LoaderKernelTests))
    report = {"schema": "hepta.runtime.authority-loader.kernel-tests.v1", "tests_run": result.testsRun,
        "expected_tests": 5, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "counts": COUNTS, "elapsed_seconds": round(time.monotonic() - started, 6),
        "backend": "unchanged-original-rust" if "HIA_AUTHORITY_REFERENCE_BINARY" in os.environ else "native-hia-probe",
        "normal_random_bytes_compared": False, "whole_runtime_replaced": False,
        "sources": {name: sha((HERE / name).read_bytes()) for name in
                    ["test_authority_loader_kernel.py", "authority_loader_supervisor.py"]}}
    passed = result.wasSuccessful() and result.testsRun == 5 and all(report[key] == 0 for key in
        ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
    expected_counts = {"processes": 110, "token_processes": 103, "owner_processes": 7,
        "kernel_supervised_processes": 26, "controlled_fault_processes": 23,
        "injected_errno_completions": 18, "injected_zero_completions": 2, "actual_fixture_mutations": 5,
        "original_owner_calls": 110 if "HIA_AUTHORITY_REFERENCE_BINARY" in os.environ else 0,
        "native_owner_calls": 0 if "HIA_AUTHORITY_REFERENCE_BINARY" in os.environ else 110}
    report["expected_counts"] = expected_counts
    report["counts_match"] = COUNTS == expected_counts
    passed = passed and report["counts_match"] and len(CASES) == 110
    report["status"] = "PASS" if passed else "FAIL"
    folder = os.environ.get("HIA_AUTHORITY_KERNEL_CORPUS_DIR")
    if folder:
        raw = (json.dumps(CASES, sort_keys=True, separators=(",", ":")) + "\n").encode()
        Path(folder, "kernel-cases.json").write_bytes(raw)
        report["cases_sha256"] = sha(raw)
        report["cases_bytes"] = len(raw)
        Path(folder, "kernel-report.json").write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if passed else 1)
