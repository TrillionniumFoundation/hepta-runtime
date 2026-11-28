#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual HIA bootstrap byte admission; SSH execution is qualified separately."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import sys
import unittest

ROOT = Path(os.environ.get("HIA_RUNTIME_REPO", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
COUNTS = {"native_calls": 0, "accepted": 0, "admission_refusals": 0, "capacity_refusals": 0}


def frame(size, root):
    return b"HLRBQ001" + struct.pack("<7Q", size, len(root), 0, 0, 0, 0, 0) + root


class BootstrapStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(os.environ["HIA_BOOTSTRAP_MANIFEST"]).resolve(strict=True)
        cls.metadata = json.loads(cls.path.read_bytes())
        cls.module = NativeModule(cls.path, manifest_sha256=hashlib.sha256(cls.path.read_bytes()).hexdigest())
        cls.addClassCleanup(cls.module.close)
        cls.source = ROOT / "native/native_read_bootstrap.hepta"
        assert hashlib.sha256(cls.source.read_bytes()).hexdigest() == cls.metadata["source_sha256"]

    def test_retained_utf8_and_authoring_source(self):
        sys.path.insert(0, os.environ["HIA_HEPTA_DIR"])
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        proof = json.loads(self.source.with_name("native_read_bootstrap_composition.json").read_bytes())
        for name, key in [("scripts/native_read_bootstrap.pseudo", "pseudo_sha256"),
                          ("scripts/author_native_read_bootstrap.py", "author_sha256"),
                          ("native/native_read_bootstrap_wire.json", "wire_sha256")]:
            self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), proof[key])
        current = assemble_program(self.source.read_bytes()).as_dict()
        self.assertEqual(render_assembly(current).encode(), self.source.read_bytes())
        before = ROOT / proof["retained_utf8"]["source"]
        self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(), proof["retained_utf8"]["source_sha256"])
        old = next(fn for fn in assemble_program(before.read_bytes()).as_dict()["functions"] if fn["name"] == "f44")
        retained = copy.deepcopy(current["functions"][-1])
        retained["name"] = "f44"
        self.assertEqual(retained, old)
        self.assertIs(proof["default_public_route"], False)

    def test_trusted_root_shell_words_and_exact_elf_extent(self):
        roots = [b"/tmp", b"/", b"/tmp/quote'\\tab\t",
                 "/tmp/new\n雪😀".encode(), b"/" + b"x"*4094]
        for root in roots:
            for size in (1, 65535, 65536, 0xfffeffff):
                result = self.module.invoke(frame(size, root), output_capacity=32768, workspace_capacity=4096)
                COUNTS["native_calls"] += 1
                self.assertEqual(result[:8], b"HLRBR001")
                self.assertEqual(struct.unpack_from("<7Q", result, 8),
                                 (size, size//65536, size%65536, len(root), 0, 0, len(result)-64))
                words = shlex.split(result[64:].decode())
                self.assertEqual(words[words.index("--local-read-profile")+1], root.decode())
                self.assertIn("iflag=fullblock", words)
                self.assertIn(str(size), words)
                COUNTS["accepted"] += 1

    def test_malformed_and_capacity_refusals_publish_no_bytes(self):
        valid = frame(1, b"/tmp")
        invalid = [b"", valid[:63], b"wronghdr"+valid[8:], frame(0, b"/tmp"),
                   frame(0xffff0000, b"/tmp"), frame(1, b""), frame(1, b"relative"),
                   frame(1, b"/\0bad"), frame(1, b"/\xff"), frame(1, b"/"+b"x"*4095),
                   valid+b"x", valid[:24]+struct.pack("<Q", 1)+valid[32:]]
        for data, output, work, expected in [(data, 32768, 4096, 0xffffffff) for data in invalid] + [
                (valid, 63, 4096, 0xfffffffe), (valid, 32768, 4095, 0xfffffffd)]:
            code, result, _ = self.module.invoke_raw(data, output_capacity=output,
                                                     workspace_capacity=work, output_fill=0xa5)
            COUNTS["native_calls"] += 1
            self.assertEqual(code, expected)
            self.assertEqual(result, bytes([0xa5])*output)
            COUNTS["admission_refusals" if expected == 0xffffffff else "capacity_refusals"] += 1


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2).result
    expected = {"native_calls": 34, "accepted": 20, "admission_refusals": 12, "capacity_refusals": 2}
    ok = result.wasSuccessful() and result.testsRun == 3 and not result.skipped and COUNTS == expected
    proof = {"schema": "hepta.runtime.native-read-bootstrap-state-test.v1",
             "status": "pass" if ok else "fail", "tests_run": result.testsRun, "skipped": len(result.skipped),
             "errors": len(result.errors), "failures": len(result.failures),
             "expected_failures": len(result.expectedFailures),
             "unexpected_successes": len(result.unexpectedSuccesses),
             "python_isolated": sys.flags.isolated, "python_optimize": sys.flags.optimize,
             "counts": COUNTS, "runtime_source_sha256": BootstrapStateTests.metadata["source_sha256"],
             "runtime_image_sha256": BootstrapStateTests.metadata["image_sha256"],
             "ssh_execution_qualified": False, "default_public_route": False}
    if os.environ.get("HIA_READ_BOOTSTRAP_STATE_RESULT"):
        Path(os.environ["HIA_READ_BOOTSTRAP_STATE_RESULT"]).write_text(json.dumps(proof, indent=2, sort_keys=True)+"\n")
    print(json.dumps(proof, sort_keys=True))
    raise SystemExit(0 if ok else 1)
