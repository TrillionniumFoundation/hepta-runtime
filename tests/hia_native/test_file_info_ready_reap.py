#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Deterministic real-ELF successful worker retirement under delayed WNOHANG.

The supervisor changes only wait/poll syscall control results. Original file
metadata and every MCP response are computed by the actual HIA composition.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(os.environ.get("HIA_RUNTIME_REPO", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "tests/hia_native"))
import test_local_service as shared
from test_file_info_guard import Session
from info_guard_supervisor import process_identity

COUNTS = {"original_info_comparisons": 0, "ready_worker_reaped_before_response": 0,
          "controlled_wnohang_zeroes": 0, "bounded_polls": 0, "poll_eintr_controls": 0}
OBSERVATIONS = []


class ReadyReapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shared.NativeServiceTests.setUpClass()
        cls.executable = shared.NativeServiceTests.executable
        cls.metadata = shared.NativeServiceTests.metadata
        cls.original = shared.NativeServiceTests.original

    def test_retained_source_and_actual_prefix(self):
        sys.path.insert(0, os.environ["HIA_HEPTA_DIR"])
        from hepta.hia_agent_assembly import assemble_program
        source = ROOT / "native/composition_packer.hepta"
        proof = json.loads((ROOT / "native/composition_ready_reap.json").read_bytes())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), proof["source_sha256"])
        baseline = subprocess.run(["git", "-C", str(ROOT), "show",
                                   proof["base_runtime_commit"] + ":native/composition_packer.hepta"],
                                  check=True, stdout=subprocess.PIPE).stdout
        self.assertEqual(hashlib.sha256(baseline).hexdigest(), proof["base_source_sha256"])
        old = assemble_program(baseline).as_dict()["functions"]
        new = assemble_program(source.read_bytes()).as_dict()["functions"]
        self.assertEqual(new[1:43], old[1:43])
        restored = copy.deepcopy(new[-1])
        self.assertEqual(restored["name"], "f43")
        restored["name"] = "f0"
        shift = proof["metadata_offset"] - proof["base_metadata_offset"]
        for block, name, value in proof["metadata_relocations"]:
            ops = [op for op in restored["blocks"][block]["ops"]
                   if op["op"] == "const" and op["out"][0]["name"] == name]
            self.assertEqual(len(ops), 1)
            self.assertEqual(ops[0]["attrs"]["value"], value + shift)
            ops[0]["attrs"]["value"] = value
        self.assertEqual(restored, old[0])
        for fn in old:
            raw = json.dumps(fn, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             proof["original_functions_sha256"][fn["name"]])
        executable = self.executable.read_bytes()
        at = proof["metadata_offset"]
        prefix = bytearray(executable[:at])
        prefix[96:112] = bytes(16)
        self.assertEqual(hashlib.sha256(prefix).hexdigest(), proof["elf_prefix_normalized_sha256"])
        self.assertEqual(struct.unpack_from("<i", executable, 228)[0] + 232, at)
        self.assertEqual(executable[proof["handoff_offset"]:proof["handoff_offset"]+5].hex(),
                         proof["handoff_replacement_hex"])
        self.assertEqual(executable[proof["shim_offset"]:proof["shim_offset"]+proof["shim_bytes"]].hex(),
                         proof["shim_hex"])
        self.assertEqual(executable[at:at+8], b"HIAMOD01")

    def retirement_case(self, mode):
        with tempfile.TemporaryDirectory(prefix="hia-ready-reap-") as name:
            root = Path(name)
            path = root / "value"
            path.write_bytes(b"actual HIA metadata under delayed worker retirement\0\xff")
            expected = self.original.main({"op": "info", "root": str(root), "path": str(path)})
            log, marker_path = root / "events.json", root / "marker.json"
            start = time.monotonic()
            with Session(self.executable, root, path, mode, log, marker_path) as service:
                service.ready()
                for index in range(2):
                    failed, result = service.tool("file_info", {"host": "native-local", "path": str(path)})
                    self.assertFalse(failed, result)
                    self.assertEqual(result, json.dumps(expected, ensure_ascii=False,
                                                       sort_keys=True, separators=(",", ":")))
                    COUNTS["original_info_comparisons"] += 1
                    if index == 0:
                        marker = json.loads(marker_path.read_bytes())
                        current = process_identity(marker["worker"])
                        self.assertTrue(current is None or
                                        current["start_ticks"] != marker["worker_start_ticks"],
                                        ("successful response exposed an unreaped worker", current))
                        COUNTS["ready_worker_reaped_before_response"] += 1
                self.assertEqual(service.call(shared.req("ping", identity=99))["result"], {})
            elapsed = time.monotonic() - start
            self.assertLess(elapsed, 5)
            observed = json.loads(log.read_bytes())
            self.assertEqual(observed["service_exit"], 0)
            waits = [e for e in observed["events"] if e["event"] == "ready_owned_wait"]
            polls = [e for e in observed["events"] if e["event"] == "ready_bounded_poll"]
            self.assertGreaterEqual(len(waits), 5)
            self.assertEqual(sum(e["controlled_zero"] for e in waits), 4)
            self.assertTrue(all(e["worker"] == marker["worker"] and e["options"] == 1 for e in waits))
            self.assertGreaterEqual(len(polls), 4)
            self.assertTrue(all(e["seconds"] == 0 and 0 < e["nanoseconds"] <= 1000000 for e in polls))
            self.assertEqual(sum(e["injected_eintr"] for e in polls), int(mode == "ready_reap_eintr"))
            COUNTS["controlled_wnohang_zeroes"] += 4
            COUNTS["bounded_polls"] += len(polls)
            COUNTS["poll_eintr_controls"] += int(mode == "ready_reap_eintr")
            OBSERVATIONS.append({"mode": mode, "elapsed_seconds": elapsed,
                                 "worker": marker["worker"], "waits": waits, "polls": polls})

    def test_ready_worker_is_reaped_before_success(self):
        self.retirement_case("ready_reap")

    def test_interrupted_bounded_poll_keeps_owned_pid(self):
        self.retirement_case("ready_reap_eintr")


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2).result
    proof = {"schema": "hepta.runtime.native-ready-reap-test.v1",
             "status": "pass" if result.wasSuccessful() else "fail",
             "tests_run": result.testsRun, "skipped": len(result.skipped),
             "errors": len(result.errors), "failures": len(result.failures),
             "expected_failures": len(result.expectedFailures),
             "unexpected_successes": len(result.unexpectedSuccesses),
             "python_isolated": sys.flags.isolated, "python_optimize": sys.flags.optimize,
             "counts": COUNTS, "observations": OBSERVATIONS,
             "actual_elf_responses": shared.COUNTS["elf_requests"],
             "synthetic_application_results": False,
             "specific_owned_pid_only": True, "original_absolute_deadline_seconds": 30}
    if hasattr(ReadyReapTests, "metadata"):
        proof["executable_sha256"] = ReadyReapTests.metadata["executable_sha256"]
    if os.environ.get("HIA_READY_REAP_RESULT"):
        Path(os.environ["HIA_READY_REAP_RESULT"]).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    print(json.dumps(proof, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
