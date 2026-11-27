#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Trace custody controls, including a real compiled non-HIA control fixture."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "native_execution_trace", Path(__file__).with_name("hia_native_execution_trace.py"))
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class TraceReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "trace"
        self.entry = self.root / "entry"
        self.lines = [f'101 execve("{self.entry}", ["fixture"], 0x0 /* 0 vars */) = 0\n',
            '102 execveat(5, "", ["child"], 0x0 /* 0 vars */, AT_EMPTY_PATH <unfinished ...>\n',
            '102 <... execveat resumed>) = 0\n', '102 +++ exited with 0 +++\n',
            '101 --- SIGCHLD {si_signo=SIGCHLD, si_pid=102} ---\n', '101 +++ exited with 0 +++\n']

    def parse(self, lines=None, **kwargs):
        self.path.write_text("".join(self.lines if lines is None else lines))
        return observer.trace_summary(self.path, self.entry, expected_pid=101, **kwargs)

    def test_split_descriptor_call_and_actual_terminal_pids_are_bound(self):
        result = self.parse(required_pids=[102])
        self.assertEqual((result["execve"], result["execveat"], result["executed_processes"]), (1, 1, 2))
        with self.assertRaisesRegex(RuntimeError, "retained native owner"):
            self.parse(required_pids=[999])

    def test_foreign_path_execution_and_descriptor_flag_spoof_are_refused(self):
        replacements = [
            '102 execve("/usr/bin/python3", ["python3"], 0x0) = 0\n',
            '102 execveat(5, "/tmp/not-empty", ["child"], 0x0, AT_EMPTY_PATH) = 0\n',
            '102 execveat(5, "", ["AT_EMPTY_PATH"], 0x0, 0) = 0\n']
        for row in replacements:
            with self.subTest(row=row), self.assertRaises(RuntimeError):
                self.parse([self.lines[0], row, *self.lines[3:]])

    def test_unmatched_resumes_truncation_and_missing_terminals_are_refused(self):
        cases = [self.lines[0:1] + self.lines[2:], self.lines[:-1],
                 self.lines[:3] + self.lines[4:], self.lines[:2] + self.lines[3:],
                 self.lines[:-1] + [self.lines[-1].rstrip("\n")]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                self.parse(rows)

    def test_trace_symlink_and_duplicate_receipt_keys_are_refused(self):
        self.path.write_text("".join(self.lines))
        link = self.root / "link"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(RuntimeError, "symlinks"):
            observer.trace_summary(link, self.entry)
        self.path.write_text('{"status":"PASS","status":"HOLD"}')
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            observer.read_json(self.path)

    def observation_fixture(self):
        self.entry.write_bytes(b"non-executable custody fixture")
        directory = self.root / "observation"
        directory.mkdir()
        trace = directory / "execution.trace"
        trace.write_text("".join([*self.lines[:3],
            '103 execveat(7, "", ["fixture-leader"], 0x0, AT_EMPTY_PATH) = 0\n',
            '103 +++ exited with 0 +++\n', *self.lines[3:]]))
        (directory / "stdout").write_bytes(b"fixture result")
        (directory / "stderr").write_bytes(b"")
        row = {"schema": observer.SCHEMA, "status": "OBSERVED_NATIVE_EXECUTION_PASS",
               "source_commit": "1" * 40, "stage": "cold", "argv": [str(self.entry)],
               "trace_argv": observer.command([str(self.entry)], directory),
               "environment": dict(observer.ENVIRONMENT), "returncode": 0, "pid": 101,
               "observed_entry_process_terminal": True, "observer_timeout": False,
               "observer_termination_requests": [], "observer": observer.pin(observer.__file__),
               "whole_stack_native": False, "entry": observer.pin(self.entry),
               "stdout": observer.pin(directory / "stdout"), "stderr": observer.pin(directory / "stderr"),
               "trace_raw": observer.pin(trace), "trace": observer.trace_summary(trace, self.entry)}
        (directory / "observation.json").write_text(json.dumps(row))
        return directory, row

    def test_owner_pid_budget_flags_and_exact_extent_are_bound(self):
        directory, row = self.observation_fixture()
        owner = self.root / "owner"
        words = [int.from_bytes(b"HIACOR01", "little"), 0, 102, 101, 1000, 180000001000,
                 180, 3000000000, 103, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 2000,
                 3000002000, 0, 1, 3000, 0, 4096, 16384, 65536, 1, 0, 0, 0]
        owner.write_bytes(struct.pack("<32Q", *words))
        expected = {"expected_argv": row["argv"], "expected_entry": row["entry"]}
        observer.admit_execution(directory, source="1" * 40, stage="cold", owner_receipt=owner, **expected)
        for index, value in [(3, 999), (6, 181), (5, 180000001001), (12, 0), (18, 1)]:
            changed = words.copy()
            changed[index] = value
            owner.write_bytes(struct.pack("<32Q", *changed))
            with self.subTest(index=index), self.assertRaisesRegex(RuntimeError, "native owner"):
                observer.admit_execution(directory, source="1" * 40, stage="cold", owner_receipt=owner, **expected)

    def test_self_reported_entry_and_full_argv_cannot_replace_trusted_inputs(self):
        directory, row = self.observation_fixture()
        original = json.loads(json.dumps(row))
        expected = {"expected_argv": [str(self.entry)], "expected_entry": observer.pin(self.entry)}
        observer.admit_execution(directory, source="1" * 40, stage="cold", **expected)
        foreign = self.root / "foreign-entry"
        foreign.write_bytes(self.entry.read_bytes())
        for argv in ([str(foreign)], [str(self.entry), "--source", "/foreign/source"],
                     [str(self.entry), "--timeout-seconds", "181"]):
            row = {**original, "argv": argv, "trace_argv": observer.command(argv, directory)}
            (directory / "observation.json").write_text(json.dumps(row))
            with self.subTest(argv=argv), self.assertRaisesRegex(RuntimeError, "trusted invocation"):
                observer.admit_execution(directory, source="1" * 40, stage="cold", **expected)
        self.entry.write_bytes(b"different purported ELF at the same selected path")
        row = {**original, "entry": observer.pin(self.entry)}
        (directory / "observation.json").write_text(json.dumps(row))
        with self.assertRaisesRegex(RuntimeError, "independently admitted tool"):
            observer.admit_execution(directory, source="1" * 40, stage="cold", **expected)

    def test_real_audit_rejection_cannot_leak_an_open_evidence_descriptor(self):
        source = Path(observer.__file__).absolute()
        helper = source.with_name("hia_native_helper_mcp_integration.py")
        self.path.write_bytes(b"audit descriptor fixture")
        code = r'''
import errno, importlib.util, os, sys
loaded = []
for index, path in enumerate(sys.argv[1:3]):
    spec = importlib.util.spec_from_file_location("audit_control_" + str(index), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded.append(module)
blocked = []
def audit(event, args):
    if event == "open" and type(args[0]) is int:
        blocked.append(args[0])
        raise PermissionError("real audit fdopen refusal")
sys.addaudithook(audit)
for index, module in enumerate(loaded):
    try:
        if index == 0:
            module.pin(sys.argv[3])
        else:
            module.ordinary_bytes(sys.argv[3], 1024)
    except PermissionError as error:
        assert str(error) == "real audit fdopen refusal"
    else:
        raise AssertionError("audit hook did not reject fdopen")
    assert len(blocked) == index + 1
    try:
        os.fstat(blocked[-1])
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("evidence descriptor leaked after audit refusal")
print("two real fdopen audit refusals closed both original descriptors")
'''
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(source), str(helper), str(self.path)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("closed both original descriptors", result.stdout)


class ActualExternalObserverControls(unittest.TestCase):
    """The C fixture tests tracing only; it is never a HIA qualification product."""
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("HIA_NATIVE_EXECUTION_CONTROL_EVIDENCE")
        cls.temporary = None if retained else tempfile.TemporaryDirectory()
        cls.root = Path(retained if retained else cls.temporary.name).resolve()
        if retained:
            cls.root.mkdir(mode=0o700, exist_ok=False)
        cls.source = cls.root / "external-observer-control.c"
        cls.entry = cls.root / "external-observer-control"
        cls.source.write_text(r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2) return 64;
  if (!strcmp(argv[1], "--child")) return 0;
  if (!strcmp(argv[1], "--failure")) return 7;
  if (!strcmp(argv[1], "--sleep")) { sleep(10); return 0; }
  int source = open(argv[0], O_RDONLY), image = memfd_create("trace-control", MFD_CLOEXEC);
  if (source < 0 || image < 0) return 65;
  char buffer[4096]; ssize_t size;
  while ((size = read(source, buffer, sizeof buffer)) > 0)
    if (write(image, buffer, size) != size) return 66;
  close(source);
  int child = fork();
  if (child == 0) {
    char *args[] = {"trace-control-child", "--child", NULL};
    char *env[] = {NULL};
    execveat(image, "", args, env, AT_EMPTY_PATH);
    _exit(67);
  }
  int status = 0;
  if (child < 0 || waitpid(child, &status, 0) != child || status != 0) return 68;
  const char data[] = "external control only\n";
  int output = open(argv[1], O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (output < 0 || write(output, data, sizeof data - 1) != sizeof data - 1) return 69;
  close(output);
  return write(1, data, sizeof data - 1) == sizeof data - 1 ? 0 : 70;
}
''')
        subprocess.run(["/usr/bin/cc", "-Wall", "-Wextra", "-Werror", str(cls.source),
                        "-o", str(cls.entry)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def test_real_detached_trace_is_admitted_then_source_result_and_log_tampering_refused(self):
        output, result = self.root / "success", self.root / "result"
        expected = {"expected_argv": [str(self.entry), str(result)], "expected_entry": observer.pin(self.entry)}
        row = observer.observe([str(self.entry), str(result)], directory=output,
            source="1" * 40, stage="cold", timeout=10, result=result)
        self.assertEqual(row["returncode"], 0)
        admitted = observer.admit_execution(output, source="1" * 40, stage="cold", expected_result=result, **expected)
        self.assertFalse(admitted["whole_stack_native"])
        self.assertEqual(admitted["trace"]["execveat"], 1)
        with self.assertRaisesRegex(RuntimeError, "another source"):
            observer.admit_execution(output, source="2" * 40, stage="cold", expected_result=result, **expected)
        changed = {**expected, "expected_argv": [str(self.entry), str(result), "--foreign-source"]}
        with self.assertRaisesRegex(RuntimeError, "trusted invocation"):
            observer.admit_execution(output, source="1" * 40, stage="cold", expected_result=result, **changed)
        raw = result.read_bytes()
        result.write_bytes(b"substituted result")
        with self.assertRaisesRegex(RuntimeError, "result bytes"):
            observer.admit_execution(output, source="1" * 40, stage="cold", expected_result=result, **expected)
        result.write_bytes(raw)
        trace = output / "execution.trace"
        trace.write_bytes(trace.read_bytes() + b'999 execve("/bin/sh", [], 0x0) = 0\n')
        with self.assertRaisesRegex(RuntimeError, "foreign path"):
            observer.admit_execution(output, source="1" * 40, stage="cold", expected_result=result, **expected)

    def test_real_valid_elf_substitution_is_refused_by_independent_entry_identity(self):
        entry, output, result = self.root / "substituted-entry", self.root / "substituted-execution", self.root / "substituted-result"
        expected = observer.pin(self.entry)
        entry.write_bytes(self.entry.read_bytes() + b"different valid ELF custody control\n")
        entry.chmod(0o700)
        argv = [str(entry), str(result)]
        row = observer.observe(argv, directory=output, source="1" * 40, stage="prebuild", timeout=10, result=result)
        self.assertEqual(row["returncode"], 0)
        self.assertGreater(row["trace"]["execveat"], 0)
        with self.assertRaisesRegex(RuntimeError, "independently admitted tool"):
            observer.admit_execution(output, source="1" * 40, stage="prebuild", expected_argv=argv,
                                     expected_entry=expected, expected_result=result)

    def test_real_failure_and_observer_timeout_preserve_actual_terminal_receipts(self):
        for name, argument, timeout, expected in [
                ("failure", "--failure", 10, 7), ("timeout", "--sleep", 0.1, -15)]:
            directory = self.root / name
            with self.subTest(name=name), self.assertRaises(Exception):
                observer.observe([str(self.entry), argument], directory=directory,
                    source="1" * 40, stage="cold", timeout=timeout)
            row = json.loads((directory / "observation.json").read_bytes())
            self.assertEqual(row["status"], "HOLD")
            self.assertEqual(row["returncode"], expected)
            self.assertTrue(row["observed_entry_process_terminal"])
            self.assertEqual(row["observer_timeout"], name == "timeout")
            self.assertIn("stdout", row)
            self.assertIn("stderr", row)


if __name__ == "__main__":
    unittest.main()
