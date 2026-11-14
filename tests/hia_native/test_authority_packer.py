"""Exercise the real HIA authority packer, cache admission and checkout paths.

The compiler is reused only from a checked development workspace. No case in
this suite claims a fresh upstream cold qualification or an original Rust run.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_authority_build import build_authority, make_frame, sha
from hia_native_authority_layout import validate_authority_layout
from hia_native_build import HEPTA_COMMIT
from hia_native_loader import NativeModule
from hia_native_entropy_qualification import inspect_elf
from hia_native_authority_qualification import PACKER_COUNTS, PACKER_SOURCES, PROFILE_SHA

COUNTS = {name: 0 for name in PACKER_COUNTS}
CONTROLS = []


def atomic(path, raw):
    pending = path.with_name(path.name + ".owned-test")
    with pending.open("xb") as stream:
        stream.write(raw)
    pending.chmod(path.stat().st_mode & 0o777)
    os.replace(pending, path)


class PackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ["HIA_AUTHORITY_ELF_MANIFEST"]).resolve(strict=True)
        cls.build_root = cls.manifest.parents[2]
        cls.hepta = Path(os.environ["HIA_HEPTA_DIR"]).resolve(strict=True)
        cls.metadata = json.loads(cls.manifest.read_bytes())
        cls.profile = json.loads((ROOT / "native/authority_profile.json").read_bytes())
        cls.provenance = json.loads((ROOT / "native/authority_packer_provenance.json").read_bytes())
        cls.original = cls.manifest.read_bytes()
        cls.exe = cls.manifest.parent / "native-authority.elf"
        cls.executable = cls.exe.read_bytes()
        cls.images = [(cls.manifest.parent / f"module_{i:02d}.image.bin").read_bytes() for i in range(9)]
        cls.frame = make_frame(cls.profile, cls.images)
        cls.packer = NativeModule(cls.manifest.parent / "packer.json",
                                  manifest_sha256=cls.metadata["packer"]["manifest_sha256"])
        cls.offsets, cursor = [], 32
        for image in cls.images:
            cls.offsets.append(cursor)
            cursor += 128 + len(image)
        assert cursor == len(cls.frame)

    @classmethod
    def tearDownClass(cls):
        cls.packer.close()
        assert cls.manifest.read_bytes() == cls.original and cls.exe.read_bytes() == cls.executable

    def invoke(self, wire, *, output=None, workspace=1 << 20):
        capacity = len(self.executable) if output is None else output
        code, returned, scratch = self.packer.invoke_raw(bytes(wire), output_capacity=capacity,
            workspace_capacity=workspace, output_fill=0xa7, workspace_fill=0)
        COUNTS["native_packer_calls"] += 1
        self.assertLessEqual(code, 0xffffffff)
        return code, returned, scratch

    def test_native_valid_and_capacity_boundaries(self):
        code, output, _ = self.invoke(self.frame)
        self.assertEqual(code, len(self.executable))
        self.assertEqual(output, self.executable)
        layout = validate_authority_layout(output, self.frame, self.profile, self.provenance)
        self.assertTrue(layout["all_actual_embedded_images_match"])
        COUNTS["valid_native_packs"] += 1
        for capacity, workspace in ((len(output) - 1, 1 << 20), (len(output), 0)):
            result, raw, _ = self.invoke(self.frame, output=capacity, workspace=workspace)
            self.assertEqual(result, 0xfffffffe)
            self.assertEqual(raw, b"\xa7" * capacity)
            COUNTS["capacity_refusals"] += 1

    def test_native_exact_profile_and_actual_image_pins(self):
        def word(offset, value):
            wire = bytearray(self.frame)
            struct.pack_into("<Q", wire, offset, value)
            return wire
        row = self.offsets
        cases = [("magic", b"X" + self.frame[1:]), ("count-eight", word(8, 8)),
            ("count-ten", word(8, 10)), ("header-reserved-one", word(16, 1)),
            ("header-reserved-two", word(24, 1)), ("root-flags", word(row[0] + 32, 0)),
            ("root-mask", word(row[0] + 40, 457)), ("root-input", word(row[0] + 8, (8 << 20) - 1)),
            ("root-output", word(row[0] + 16, (8 << 20) - 1)),
            ("root-workspace", word(row[0] + 24, (16 << 20) - 1)),
            ("old-codec-capacity", word(row[3] + 16, 32)), ("entropy-flag", word(row[7] + 32, 0)),
            ("loader-flag", word(row[8] + 32, 0)), ("loader-input", word(row[8] + 8, 131096)),
            ("member-reserved", word(row[0] + 48, 1)), ("trailing-byte", self.frame + b"\0")]
        for label, wire in cases:
            with self.subTest(label=label):
                code, _, _ = self.invoke(wire)
                self.assertEqual(code, 0xffffffff)
                COUNTS["profile_refusals"] += 1
                CONTROLS.append({"kind": "native-profile", "case": label, "code": code})
        offsets = [(f"actual-image-{i}", row[i] + 128 + len(image) // 2) for i, image in enumerate(self.images)]
        offsets += [("source-tag", row[0] + 64), ("image-tag", row[0] + 96)]
        for label, offset in offsets:
            with self.subTest(label=label):
                wire = bytearray(self.frame)
                wire[offset] ^= 1
                code, _, _ = self.invoke(wire)
                self.assertEqual(code, 0xffffffff)
                COUNTS["image_pin_refusals"] += 1
                CONTROLS.append({"kind": "native-image", "case": label, "code": code})

    def test_actual_cached_native_build_rejects_rehashed_substitution(self):
        with tempfile.TemporaryDirectory(prefix="authority-native-cache-") as temporary:
            target = Path(temporary) / "build"
            # A CI temporary directory may be a different filesystem. A real
            # copy also prevents a mutation from ever changing the input cache.
            shutil.copytree(self.build_root, target)
            manifest = target / self.manifest.relative_to(self.build_root)
            executable = manifest.parent / self.exe.name

            def invoke(expected=None):
                COUNTS["cached_build_checks"] += 1
                if expected is None:
                    self.assertEqual(build_authority(self.hepta, target, source_root=ROOT), manifest)
                    return
                with self.assertRaisesRegex(ValueError, expected):
                    build_authority(self.hepta, target, source_root=ROOT)
                COUNTS["cached_build_refusals"] += 1

            invoke()
            for label in ("missing-compiler-commit", "wrong-compiler-commit"):
                changed = json.loads(self.original)
                if label.startswith("missing"):
                    del changed["compiler_commit"]
                else:
                    changed["compiler_commit"] = "0" * 40
                atomic(manifest, (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode())
                invoke("cached top-level compiler/profile differs")
                CONTROLS.append({"kind": "actual-cache", "case": label, "refused": True})
                atomic(manifest, self.original)
            descriptor = self.provenance["metadata_offset"] + 64
            mutations = []
            raw = bytearray(self.executable); raw[descriptor + 16] ^= 1
            mutations.append(("rehashed-capability-table", raw))
            first_image = struct.unpack_from("<Q", self.executable, descriptor)[0]
            raw = bytearray(self.executable); raw[first_image + 17] ^= 1
            mutations.append(("rehashed-actual-image", raw))
            raw = bytearray(self.executable); raw[self.provenance["metadata_hole"]] ^= 1
            mutations.append(("rehashed-metadata-pointer", raw))
            raw = bytearray(self.executable + b"\0")
            struct.pack_into("<2Q", raw, 96, len(raw), len(raw))
            mutations.append(("rehashed-trailing-byte", raw))
            for label, raw in mutations:
                changed = json.loads(self.original)
                changed["executable_sha256"] = sha(raw)
                changed["inspection"] = inspect_elf(bytes(raw))
                changed.pop("layout", None)
                atomic(executable, bytes(raw))
                atomic(manifest, (json.dumps(changed, indent=2, sort_keys=True) + "\n").encode())
                invoke("authority ELF layout")
                CONTROLS.append({"kind": "actual-cache", "case": label, "refused": True})
                atomic(executable, self.executable)
                atomic(manifest, self.original)
            invoke()

    def test_arbitrary_checkout_uses_its_own_repository_root(self):
        with tempfile.TemporaryDirectory(prefix="authority-nonstandard-checkout-") as temporary:
            alternative = Path(temporary) / "arbitrary-checkout"
            names = {row["source"] for row in self.profile["members"]}
            names.update({"native/authority_profile.json", "native/authority_packer_provenance.json",
                "native/authority_packer.hepta", "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
                "scripts/hia_native_entropy_qualification.py", "scripts/hia_native_authority_build.py",
                "scripts/hia_native_authority_layout.py", "tests/hia_native/authority_native_harness.py",
                "tests/hia_native/scope_entropy_fixture.hepta"})
            for name in names:
                path = alternative / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            environment = {key: value for key, value in os.environ.items() if not key.startswith("HIA_")}
            help_run = subprocess.run([sys.executable, "-I", "-B",
                str(alternative / "scripts/hia_native_authority_build.py"), "--help"],
                cwd=temporary, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(help_run.returncode, 0, help_run.stderr)
            self.assertIn(b"--build-root", help_run.stdout)
            self.assertEqual(help_run.stderr, b"")
            COUNTS["arbitrary_checkout_processes"] += 1
            code = """
from pathlib import Path
import sys
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'tests/hia_native'))
from authority_native_harness import Modules,Harness,frame,response
modules=Modules(*sys.argv[2:5]);h=Harness(modules,mode=1)
try:
    assert h.startup()==(0,b'')
    status,wire=h.request(frame(1))
    assert status==len(wire) and response(wire)==(0,b'\\0')
    assert h.shutdown()==(0,b'')
finally:
    h.close();modules.close()
print('PASS')
"""
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(alternative),
                str(self.manifest.parent / "module_00.json"), str(self.manifest.parent / "module_08.json"),
                os.environ["HIA_SCOPE_MANIFEST"]], cwd=temporary, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"PASS\n"); self.assertEqual(result.stderr, b"")
            COUNTS["arbitrary_checkout_processes"] += 1
            COUNTS["arbitrary_checkout_native_requests"] += 1


if __name__ == "__main__":
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PackerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "hepta.runtime.authority-packer.tests.v1",
        "tests_run": result.testsRun, "expected_tests": 4, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "counts": COUNTS, "expected_counts": PACKER_COUNTS, "counts_match": COUNTS == PACKER_COUNTS,
        "sources": {name: sha((ROOT / name).read_bytes()) for name in PACKER_SOURCES},
        "compiler_commit": HEPTA_COMMIT, "profile_sha256": PROFILE_SHA,
        "elapsed_seconds": round(time.monotonic() - started, 6), "controls": CONTROLS,
        "fresh_compiler_cold_claimed": False, "whole_runtime_replaced": False}
    manifest = Path(os.environ["HIA_AUTHORITY_ELF_MANIFEST"])
    metadata = json.loads(manifest.read_bytes())
    report.update(compiler_sha256=metadata["compiler_sha256"], manifest_sha256=sha(manifest.read_bytes()),
                  executable_sha256=sha((manifest.parent / metadata["executable"]).read_bytes()))
    passed = result.wasSuccessful() and result.testsRun == 4 and report["counts_match"] and all(report[name] == 0 for name in
        ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
    report["status"] = "PASS" if passed else "FAIL"
    if os.environ.get("HIA_AUTHORITY_PACKER_REPORT"):
        path = Path(os.environ["HIA_AUTHORITY_PACKER_REPORT"])
        with path.open("x") as stream: stream.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if passed else 1)
