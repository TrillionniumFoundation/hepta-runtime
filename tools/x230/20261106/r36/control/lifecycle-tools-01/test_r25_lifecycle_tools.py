#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Local gate/exec and arithmetic regressions; no SSH server or remote workload."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

import analyze_lifecycle_gates as metrics
import cancel_saturation_gate as gate


class GateFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-r25-gate-test-")
        self.root = Path(self.temporary.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        original = self.bin / "ssh"
        gate.create(original, b'''#!/usr/bin/python3
import json, sys
print(json.dumps({'argv':sys.argv[1:], 'stdin_hex':sys.stdin.buffer.read().hex()}))
''', 0o700)
        self.command = "one frozen read-only command"
        self.predicate = self.root / "predicate.json"
        gate.create(self.predicate, gate.canonical({"schema":"hepta-r25-fixed-status-predicate/v1",
                                                  "remote_command_sha256":gate.sha(self.command.encode())}))
        self.wrapper, self.binding = gate.install_wrapper(original, self.root, self.predicate)
        raw_stat = Path("/proc/self/stat").read_text()
        raw_pid = int(raw_stat.split("(", 1)[0])
        fields = raw_stat[raw_stat.rfind(") ") + 2:].split()
        self.proc_namespace_matches = raw_pid == os.getpid()
        self.controller = {"pid":os.getpid(), "birth_ticks":int(fields[19])}
        self.query = {"job_id":"original-job", "job_dir":"/owned/jobs/original-job", "unit":"original-unit",
                      "request_digest":"a"*64, "wait_seconds":0}
        self.processes = []

    def tearDown(self):
        for child in self.processes:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
        self.temporary.cleanup()

    def configure(self, seconds=8, controller=None):
        now = time.monotonic_ns()
        self.config = {"nonce":"local-test", "controller":controller or self.controller,
                       "status_command_sha256":gate.sha(self.command.encode()),
                       "created_monotonic_ns":now, "expires_monotonic_ns":now+int(seconds*1e9),
                       "bindings":{"rog":{"ssh_target":"owned.invalid", "request":self.query}}}
        gate.create(self.root / "saturation-gate/config.json", gate.canonical(self.config))

    def launch(self, command=None, query=None, new_parent=False):
        raw = b" \n" + json.dumps(query or self.query).encode() + b"\n\t"
        argv = [str(self.wrapper), "-T", "owned.invalid", command or self.command]
        if new_parent:
            argv = ["/usr/bin/python3", "-c",
                    "import subprocess,sys; r=subprocess.run(sys.argv[1:],input=sys.stdin.buffer.read()); raise SystemExit(r.returncode)", *argv]
        child = subprocess.Popen(argv,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(child)
        child.stdin.write(raw)
        child.stdin.close()
        child.stdin = None
        return child, raw

    def forwarded(self, child, raw, command=None):
        out, err = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, err)
        self.assertEqual(json.loads(out), {"argv":["-T","owned.invalid",command or self.command], "stdin_hex":raw.hex()})

    def test_inactive_gate_execs_original_with_identical_payload(self):
        child, raw = self.launch()
        self.forwarded(child, raw)

    def test_only_exact_original_status_waits_and_release_preserves_stdin(self):
        if not self.proc_namespace_matches:
            self.skipTest("executor PID namespace differs from /proc; exact owned-Child test must run on X230")
        self.configure()
        child, raw = self.launch()
        until = time.monotonic()+2
        while not list((self.root / "saturation-gate").glob("ready-*.json")):
            self.assertIsNone(child.poll())
            self.assertLess(time.monotonic(), until)
            time.sleep(.005)
        self.assertIsNone(child.poll())
        ready = json.loads(next((self.root / "saturation-gate").glob("ready-*.json")).read_bytes())
        self.assertEqual(ready["pid"], child.pid)
        self.assertEqual(ready["request"], self.query)
        self.assertEqual(ready["raw_request_sha256"], gate.sha(raw))
        gate.create(self.root / "saturation-gate/release.json", gate.canonical(
            {"nonce":"local-test", "controller":self.controller, "released_monotonic_ns":time.monotonic_ns()}))
        self.forwarded(child, raw)
        # The original held transport has now drained. A replacement controller
        # is still denied until retirement; it may not merely reuse release.json.
        replacement, _ = self.launch(new_parent=True)
        out, err = replacement.communicate(timeout=3)
        self.assertNotEqual(replacement.returncode, 0)
        self.assertFalse(out)
        self.assertIn(b"controller binding changed", err)
        config_raw = (self.root / "saturation-gate/config.json").read_bytes()
        gate.retire_config(self.root / "saturation-gate", gate.sha(config_raw), self.controller, "local-test")
        replacement, replacement_raw = self.launch(new_parent=True)
        self.forwarded(replacement, replacement_raw)
        self.assertEqual((self.root / "saturation-gate/config.closed.json").read_bytes(), config_raw)

    def test_effect_command_is_never_gated_even_with_identical_query(self):
        self.configure()
        child, raw = self.launch(command="a cancellation command")
        self.forwarded(child, raw, command="a cancellation command")
        self.assertFalse(list((self.root / "saturation-gate").glob("ready-*.json")))

    def test_other_job_status_is_not_gated_or_rewritten(self):
        self.configure()
        child, raw = self.launch(query={**self.query, "job_id":"different-job"})
        self.forwarded(child, raw)
        self.assertFalse(list((self.root / "saturation-gate").glob("ready-*.json")))

    def test_changed_controller_refuses_without_exec(self):
        if not self.proc_namespace_matches:
            self.skipTest("executor PID namespace differs from /proc; exact owned-Child test must run on X230")
        self.configure(controller={**self.controller, "birth_ticks":self.controller["birth_ticks"]+1})
        child, _ = self.launch()
        out, err = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0)
        self.assertFalse(out)
        self.assertIn(b"controller binding changed", err)
        self.assertFalse(list((self.root / "saturation-gate").glob("ready-*.json")))

    def test_expired_gate_does_not_forward_or_retry(self):
        if not self.proc_namespace_matches:
            self.skipTest("executor PID namespace differs from /proc; exact owned-Child test must run on X230")
        self.configure(seconds=.1)
        child, _ = self.launch()
        out, err = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0)
        self.assertFalse(out)
        self.assertIn(b"gate expired", err)

    def test_released_gate_keeps_owner_check_until_explicit_retirement_then_restart_passes(self):
        # A replacement parent is still refused while the old gate is active,
        # even when release exists. Only explicit post-drain retirement bypasses it.
        prior = {**self.controller, "birth_ticks":self.controller["birth_ticks"]+1}
        self.configure(controller=prior)
        release = {"nonce":"local-test", "controller":prior, "released_monotonic_ns":time.monotonic_ns()}
        gate.create(self.root / "saturation-gate/release.json", gate.canonical(release))
        child, _ = self.launch()
        out, err = child.communicate(timeout=3)
        self.assertNotEqual(child.returncode, 0)
        self.assertFalse(out)
        self.assertIn(b"controller binding changed", err)
        raw = (self.root / "saturation-gate/config.json").read_bytes()
        retired = gate.retire_config(self.root / "saturation-gate", gate.sha(raw), prior, "local-test")
        self.assertTrue(retired["directory_synced"])
        self.assertEqual((self.root / "saturation-gate/config.closed.json").read_bytes(), raw)
        self.assertFalse((self.root / "saturation-gate/config.json").exists())
        child, payload = self.launch()
        self.forwarded(child, payload)
        self.assertFalse(list((self.root / "saturation-gate").glob("ready-*.json")))


class Arithmetic(unittest.TestCase):
    def test_rpc_group_uses_complete_phase_spans_and_clock_resolution(self):
        cells = [{"phase":"launch", "latencies_ms":[1,2,3,4,5,6], "rpc_span_seconds":.1,
                  "controller_cpu_seconds":.03, "controller_and_waited_child_cpu_seconds":.08,
                  "clock_ticks_per_second":100},
                 {"phase":"launch", "latencies_ms":[7,8,9,10,11,12], "rpc_span_seconds":.2,
                  "controller_cpu_seconds":.04, "controller_and_waited_child_cpu_seconds":.09,
                  "clock_ticks_per_second":100}]
        result = metrics.group(cells, ("launch",))
        self.assertEqual(result["calls"], 12)
        self.assertAlmostEqual(result["rpc_per_second"], 40)
        self.assertEqual(result["rpc_p95_ms"], 12)
        self.assertAlmostEqual(result["controller_cpu_seconds"], .07)
        self.assertAlmostEqual(result["controller_and_waited_child_cpu_seconds"], .17)
        self.assertEqual(result["quantization_tolerance_seconds"], .02)
        cells[0]["latencies_ms"].pop()
        with self.assertRaises(ValueError):
            metrics.group(cells, ("launch",))

    def test_percentile_rejects_nonfinite_or_empty_samples(self):
        for values in ([], [float("nan")], [float("inf")], [-1]):
            with self.assertRaises(ValueError):
                metrics.p95(values)


if __name__ == "__main__":
    unittest.main()
