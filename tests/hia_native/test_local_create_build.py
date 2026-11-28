"""Execute packer controls and refuse changed source-bound create artifacts."""
from __future__ import annotations

import collections
import ctypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
from hia_native_local_create_build import COMPONENT, SOURCES, digest, source_evidence, verify_build

COUNTS = collections.Counter()
OUTPUT = Path(os.environ["HIA_LOCAL_CREATE_OUTPUT"]) / "build-controls"
MANIFEST = Path(os.environ["HIA_LOCAL_CREATE_MANIFEST"])


class BuildControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUTPUT.mkdir(parents=True, exist_ok=False)
        cls.metadata = verify_build(MANIFEST, source_root=ROOT)
        cls.component = source_evidence(ROOT)

    def test_01_fixed_bridge_source(self):
        commands = [
            ["as", "--64", "-o", str(OUTPUT / "adapter.o"), str(ROOT / "scripts/local_create_adapter.S")],
            ["objcopy", "-O", "binary", "-j", ".text", str(OUTPUT / "adapter.o"), str(OUTPUT / "adapter.bin")],
            ["readelf", "-r", str(OUTPUT / "adapter.o")],
        ]
        records = []
        for index, command in enumerate(commands):
            run = subprocess.run(command, capture_output=True, timeout=30)
            COUNTS["actual_assembler_processes"] += 1
            for stream in ("stdout", "stderr"):
                (OUTPUT / (str(index) + "." + stream)).write_bytes(getattr(run, stream))
            records.append({"command": command, "exit_code": run.returncode, "timeout_seconds": 30,
                            **{stream: {"bytes": len(getattr(run, stream)), "sha256": digest(getattr(run, stream))}
                               for stream in ("stdout", "stderr")}})
            (OUTPUT / "assembler-processes.json").write_text(json.dumps(records, indent=2) + "\n")
            self.assertEqual(run.returncode, 0)
        self.assertIn(b"There are no relocations", run.stdout)
        raw = (OUTPUT / "adapter.bin").read_bytes()
        self.assertEqual(raw[-1:], b"\xcc")
        self.assertEqual(raw[:-1], bytes.fromhex(self.component["prefix_hex"])[176:])
        COUNTS["complete_adapter_comparisons"] += 1

    def test_02_actual_packer(self):
        image = (MANIFEST.parent / "owner.image.bin").read_bytes()
        valid = b"HLCREPK1" + struct.pack("<Q", len(image)) + image
        expected = (MANIFEST.parent / "local-create.elf").read_bytes()
        cases = [("exact", valid, len(expected), len(expected)),
                 ("tail", valid, len(expected) + 37, len(expected)),
                 ("short-output", valid, len(expected) - 1, 0xfffffffe),
                 ("zero-output", valid, 0, 0xfffffffe),
                 ("magic", b"X" + valid[1:], len(expected), 0xffffffff),
                 ("length-low", valid[:8] + struct.pack("<Q", len(image) - 1) + image, len(expected), 0xffffffff),
                 ("length-high", valid[:8] + struct.pack("<Q", len(image) + 1) + image, len(expected), 0xffffffff),
                 ("empty-image", b"HLCREPK1" + bytes(8), len(expected), 0xffffffff)]
        cases.extend(("short-" + str(size), valid[:size], len(expected), 0xffffffff) for size in range(16))
        records = []
        with NativeModule(MANIFEST.parent / "packer.json", manifest_sha256=digest((MANIFEST.parent / "packer.json").read_bytes())) as module:
            for name, wire, capacity, code in cases:
                initial = [wire, b"\xa7" * capacity, b"\x5a" * 64]
                guards = [(b"i" * 16, b"I" * 16), (b"o" * 16, b"O" * 16), (b"w" * 16, b"W" * 16)]
                before = [left + value + right for (left, right), value in zip(guards, initial)]
                arrays = [ctypes.create_string_buffer(raw, len(raw)) for raw in before]
                args = []
                for array, value in zip(arrays, initial):
                    args.extend((ctypes.addressof(array) + 16, len(value)))
                with module._lock:
                    actual = module._entry(*args)
                COUNTS["actual_packer_calls"] += 1
                after = [array.raw for array in arrays]
                folder = OUTPUT / name
                folder.mkdir()
                for phase, buffers in (("before", before), ("after", after)):
                    for index, raw in enumerate(buffers):
                        (folder / (phase + str(index) + ".bin")).write_bytes(raw)
                self.assertEqual(actual, code)
                self.assertEqual(after[0], before[0])
                self.assertEqual(after[2], before[2])
                for raw, (left, right) in zip(after, guards):
                    self.assertEqual(raw[:16], left)
                    self.assertEqual(raw[-16:], right)
                body = after[1][16:-16]
                if actual < 0xffff0000:
                    self.assertEqual(body[:actual], expected)
                    self.assertEqual(body[actual:], initial[1][actual:])
                else:
                    self.assertEqual(after[1], before[1])
                records.append({"name": name, "returned": actual, "capacities": [len(value) for value in initial],
                                "complete_arrays_checked": True})
                (OUTPUT / "packer-calls.json").write_text(json.dumps(records, indent=2) + "\n")

    def test_03_source_and_artifact_refusals(self):
        def change_json(path, field, value):
            data = json.loads(path.read_bytes())
            data[field] = value
            path.write_text(json.dumps(data) + "\n")

        def flip_last(path):
            raw = path.read_bytes()
            path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))

        edits = [
            ("schema", "manifest.json", lambda p: change_json(p, "schema", "changed")),
            ("activation-bool", "manifest.json", lambda p: change_json(p, "production_activated", True)),
            ("activation-number", "manifest.json", lambda p: change_json(p, "production_activated", 0)),
            ("compiler", "manifest.json", lambda p: change_json(p, "compiler_sha256", "0" * 64)),
            ("owner-source", "owner.hepta", lambda p: p.write_bytes(p.read_bytes() + b"\n")),
            ("owner-image", "owner.image.bin", flip_last),
            ("packer-source", "packer.hepta", lambda p: p.write_bytes(p.read_bytes() + b"\n")),
            ("packer-image", "packer.image.bin", flip_last),
            ("owner-capacity", "owner.json", lambda p: change_json(p, "workspace_capacity", 0)),
            ("elf", "local-create.elf", lambda p: p.write_bytes(b"X" + p.read_bytes()[1:])),
            ("pack-input", "pack.input.bin", lambda p: p.write_bytes(b"X" + p.read_bytes()[1:])),
            ("pack-output-tail", "pack.output.bin", flip_last),
            ("pack-receipt", "pack.receipt.json", lambda p: change_json(p, "core_u32", True)),
            ("pack-source-custody", "pack.receipt.json", lambda p: change_json(p, "source_unchanged", False)),
        ]
        records = []
        for name, relative, edit in edits:
            with tempfile.TemporaryDirectory(prefix="artifact-", dir=OUTPUT) as temporary:
                target = Path(temporary) / "copy"
                shutil.copytree(MANIFEST.parent, target)
                path = target / relative
                before = path.read_bytes()
                path.chmod(path.stat().st_mode | 0o200)
                edit(path)
                self.assertNotEqual(before, path.read_bytes())
                with self.assertRaises((ValueError, KeyError, TypeError, json.JSONDecodeError)):
                    verify_build(target / "manifest.json", source_root=ROOT)
                COUNTS["artifact_refusals"] += 1
                records.append(name)
        for relative in (*SOURCES.values(), "scripts/local_create_adapter.S", COMPONENT):
            with tempfile.TemporaryDirectory(prefix="source-", dir=OUTPUT) as temporary:
                target = Path(temporary)
                for name in (*SOURCES.values(), "scripts/local_create_adapter.S", COMPONENT):
                    (target / name).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, target / name)
                path = target / relative
                if relative == COMPONENT:
                    change_json(path, "whole_runtime_replaced", True)
                else:
                    path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises((ValueError, KeyError, TypeError, json.JSONDecodeError)):
                    source_evidence(target)
                COUNTS["source_refusals"] += 1
                records.append(relative)
        self.assertEqual(verify_build(MANIFEST, source_root=ROOT), self.metadata)
        COUNTS["valid_artifact_admissions"] += 1
        (OUTPUT / "refusals.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BuildControls))
    summary = {"schema": "hepta.runtime.local-create-build-controls.v1",
               "status": "PASS" if result.wasSuccessful() and result.testsRun == 3 else "FAIL",
               "tests_run": result.testsRun, "expected_tests": 3,
               "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
               "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
               "counts": dict(COUNTS), "manifest_sha256": digest(MANIFEST.read_bytes())}
    if OUTPUT.is_dir():
        (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    raise SystemExit(0 if summary["status"] == "PASS" else 1)
